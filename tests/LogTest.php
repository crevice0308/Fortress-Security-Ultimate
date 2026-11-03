<?php
/**
 * Privacy, retention and filesystem boundary tests.
 *
 * @package FortressSecurityUltimate
 */

namespace Fortress\Security\Tests;

// phpcs:disable WordPress.WP.AlternativeFunctions -- Isolated fixtures intentionally exercise native filesystem boundaries without WordPress.

use Fortress\Security\Log\Exporter;
use Fortress\Security\Log\Logger;
use Fortress\Security\Log\Redactor;
use PHPUnit\Framework\TestCase;

/** Verify private diagnostic storage and export security. */
final class LogTest extends TestCase {
	/** Temporary test directory.
	 *
	 * @var string
	 */
	private string $base;
	/** Test clock.
	 *
	 * @var int
	 */
	private int $now;

	/**
	 * Verify setUp.
	 *
	 * @return void
	 */
	protected function setUp(): void {
		$this->base = sys_get_temp_dir() . '/fsu-log-test-' . bin2hex( random_bytes( 8 ) );
		mkdir( $this->base, 0700 );
		mkdir( $this->base . '/web', 0700 );
		$this->now = (int) strtotime( '2026-11-03T12:30:00Z' );
	}

	/**
	 * Verify tearDown.
	 *
	 * @return void
	 */
	protected function tearDown(): void {
		$iterator = new \RecursiveIteratorIterator( new \RecursiveDirectoryIterator( $this->base, \FilesystemIterator::SKIP_DOTS ), \RecursiveIteratorIterator::CHILD_FIRST );
		foreach ( $iterator as $entry ) {
			if ( $entry->isDir() && ! $entry->isLink() ) {
				rmdir( $entry->getPathname() );
			} else {
				unlink( $entry->getPathname() );
			}
		}
		rmdir( $this->base );
	}

	/**
	 * Create an isolated test logger.
	 *
	 * @param bool  $debug Enable debug events.
	 * @param array $categories Category filter.
	 * @param int   $max_bytes Storage capacity.
	 * @return Logger
	 */
	private function logger( bool $debug = true, array $categories = array(), int $max_bytes = 524288000 ): Logger {
		return new Logger( $this->base . '/private', array( $this->base . '/web' ), $debug, $categories, $max_bytes, fn(): int => $this->now );
	}

	/**
	 * Verify raw secrets and identifiers never enter structured records.
	 *
	 * @return void
	 */
	public function test_raw_secrets_and_identifiers_never_enter_structured_records(): void {
		$logger = $this->logger();
		self::assertTrue(
			$logger->log(
				'Error',
				'php',
				'php.error',
				array(
					'message'     => 'password=SECRET',
					'Cookie'      => 'SESSION',
					'api_token'   => 'TOKEN',
					'license_key' => 'LICENSE',
					'ip'          => '192.0.2.1',
					'url'         => 'https://example.test/?key=SECRET',
					'nested'      => array( 'password' => 'SECRET' ),
					'error_type'  => 2,
					'line'        => 12,
					'success'     => false,
				)
			)
		);
		$raw = file_get_contents( $logger->files()[0] );
		self::assertIsString( $raw );
		foreach ( array( 'SECRET', 'SESSION', 'TOKEN', 'LICENSE', '192.0.2.1', 'example.test', 'password', 'nested' ) as $forbidden ) {
			self::assertStringNotContainsString( $forbidden, $raw );
		}
		$record = json_decode( $raw, true, 8, JSON_THROW_ON_ERROR );
		self::assertSame(
			array(
				'error_type' => 2,
				'line'       => 12,
				'success'    => false,
			),
			$record['context']
		);
		self::assertSame( '2026-11-03T12:30:00Z', $record['timestamp'] );
		if ( '\\' !== DIRECTORY_SEPARATOR ) {
			self::assertSame( 0700, fileperms( $logger->directory() ) & 0777 );
			self::assertSame( 0600, fileperms( $logger->files()[0] ) & 0777 );
		}
	}

	/**
	 * Verify arbitrary codes and numeric strings are redacted.
	 *
	 * @return void
	 */
	public function test_arbitrary_codes_and_numeric_strings_are_redacted(): void {
		self::assertSame( 'event.redacted', Redactor::event( 'sk_live_credential' ) );
		self::assertSame(
			array(),
			Redactor::context(
				array(
					'count'       => '001234567890',
					'version'     => 'SECRET',
					'duration_ms' => INF,
					'commit'      => 'SECRET',
				)
			)
		);
	}

	/**
	 * Verify public document root is rejected.
	 *
	 * @return void
	 */
	public function test_public_document_root_is_rejected(): void {
		$this->expectException( \RuntimeException::class );
		new Logger( $this->base . '/web/logs', array( $this->base . '/web' ) );
	}


	/**
	 * Verify unrelated directories are rejected without changing their permissions.
	 *
	 * @return void
	 */
	public function test_non_dedicated_directory_is_not_modified(): void {
		mkdir( $this->base . '/shared', 0755 );
		file_put_contents( $this->base . '/shared/unrelated.txt', 'preserved' );
		$before = fileperms( $this->base . '/shared' );
		try {
			new Logger( $this->base . '/shared', array( $this->base . '/web' ) );
			self::fail( 'A shared directory was accepted.' );
		} catch ( \RuntimeException $error ) {
			self::assertStringContainsString( 'dedicated', $error->getMessage() );
		}
		self::assertSame( $before, fileperms( $this->base . '/shared' ) );
		self::assertSame( 'preserved', file_get_contents( $this->base . '/shared/unrelated.txt' ) );
	}

	/**
	 * Verify relative and parent traversal paths are rejected.
	 *
	 * @return void
	 */
	public function test_relative_and_parent_traversal_paths_are_rejected(): void {
		foreach ( array( 'logs', $this->base . '/private/../web' ) as $path ) {
			try {
				new Logger( $path );
				self::fail( 'An unsafe path was accepted.' );
			} catch ( \RuntimeException $error ) {
				self::assertStringContainsString( 'absolute', $error->getMessage() );
			}
		}
	}

	/**
	 * Verify symlink directory and hourly file cannot redirect writes.
	 *
	 * @return void
	 */
	public function test_symlink_directory_and_hourly_file_cannot_redirect_writes(): void {
		if ( ! function_exists( 'symlink' ) || '\\' === DIRECTORY_SEPARATOR ) {
			self::markTestSkipped( 'Symlink tests require Unix symlink support.' );
		}
		symlink( $this->base . '/web', $this->base . '/alias' );
		try {
			new Logger( $this->base . '/alias/logs', array( $this->base . '/web' ) );
			self::fail( 'Symlink parent was accepted.' );
		} catch ( \RuntimeException $error ) {
			self::assertStringContainsString( 'symlink', $error->getMessage() );
		}
		$logger = $this->logger();
		$target = $this->base . '/victim';
		file_put_contents( $target, 'preserved' );
		symlink( $target, $logger->directory() . '/fsu-20261103-12.jsonl' );
		self::assertFalse( $logger->log( 'info', 'system', 'plugin.boot' ) );
		self::assertSame( 'preserved', file_get_contents( $target ) );
	}


	/**
	 * Verify hardlinked hourly files cannot redirect writes.
	 *
	 * @return void
	 */
	public function test_hardlinked_hourly_files_cannot_redirect_writes(): void {
		if ( ! function_exists( 'link' ) || '\\' === DIRECTORY_SEPARATOR ) {
			self::markTestSkipped( 'Hardlink tests require Unix hardlink support.' );
		}
		$logger = $this->logger();
		$target = $this->base . '/victim';
		file_put_contents( $target, 'preserved' );
		link( $target, $logger->directory() . '/fsu-20261103-12.jsonl' );
		self::assertFalse( $logger->log( 'info', 'system', 'plugin.boot' ) );
		self::assertSame( 'preserved', file_get_contents( $target ) );
	}

	/**
	 * Verify debug switch and category filter keep errors.
	 *
	 * @return void
	 */
	public function test_debug_switch_and_category_filter_keep_errors(): void {
		$logger = $this->logger( false, array( 'admin' => false ) );
		self::assertFalse( $logger->log( 'debug', 'system', 'plugin.boot' ) );
		self::assertFalse( $logger->log( 'trace', 'system', 'plugin.boot' ) );
		self::assertFalse( $logger->log( 'info', 'admin', 'admin.action' ) );
		self::assertTrue( $logger->log( 'error', 'admin', 'internal.error' ) );
		self::assertCount( 1, $logger->files() );
	}


	/**
	 * Verify category lists exclude unselected info but keep errors.
	 *
	 * @return void
	 */
	public function test_category_lists_exclude_unselected_info_but_keep_errors(): void {
		$logger = $this->logger( true, array( 'php' ) );
		self::assertTrue( $logger->log( 'info', 'php', 'php.error' ) );
		self::assertFalse( $logger->log( 'info', 'admin', 'admin.action' ) );
		self::assertTrue( $logger->log( 'error', 'admin', 'internal.error' ) );
	}

	/**
	 * Verify rotation and exact 168 hour retention.
	 *
	 * @return void
	 */
	public function test_rotation_and_exact_168_hour_retention(): void {
		$logger = $this->logger();
		self::assertTrue( $logger->log( 'info', 'system', 'plugin.boot', array( 'count' => 1 ) ) );
		$this->now += 1200;
		self::assertTrue( $logger->log( 'info', 'system', 'plugin.boot', array( 'count' => 2 ) ) );
		$this->now += 3600;
		self::assertTrue( $logger->log( 'info', 'system', 'plugin.boot', array( 'count' => 3 ) ) );
		self::assertCount( 2, $logger->files() );
		$this->now = (int) strtotime( '2026-11-10T12:31:00Z' );
		$logger->prune();
		$raw = file_get_contents( $logger->files()[0] );
		self::assertStringNotContainsString( '"count":1', $raw );
		self::assertStringContainsString( '"count":2', $raw );
		$this->now += 7200;
		$logger->prune();
		self::assertCount( 0, $logger->files() );
	}


	/**
	 * Verify request writes leave the cutoff bucket to scheduled cleanup.
	 *
	 * @return void
	 */
	public function test_request_writes_do_not_compact_the_cutoff_bucket(): void {
		$logger = $this->logger();
		$logger->log( 'info', 'system', 'plugin.boot', array( 'count' => 1 ) );
		$this->now += 1200;
		$logger->log( 'info', 'system', 'plugin.boot', array( 'count' => 2 ) );
		$partial   = $logger->files()[0];
		$before    = file_get_contents( $partial );
		$this->now = (int) strtotime( '2026-11-10T12:31:00Z' );
		self::assertTrue( $logger->log( 'info', 'system', 'plugin.started' ) );
		self::assertSame( $before, file_get_contents( $partial ) );
		$logger->prune();
		self::assertStringNotContainsString( '"count":1', file_get_contents( $partial ) );
		self::assertStringContainsString( '"count":2', file_get_contents( $partial ) );
	}

	/**
	 * Verify capacity deletes oldest logs before appending.
	 *
	 * @return void
	 */
	public function test_capacity_deletes_oldest_logs_before_appending(): void {
		$logger = $this->logger( true, array(), 4096 );
		for ( $i = 0; $i < 50; ++$i ) {
			self::assertTrue( $logger->log( 'info', 'system', 'plugin.boot', array( 'count' => $i ) ) );
			$this->now += 3600;
		}
		self::assertLessThanOrEqual( 4096, $logger->stats()['size_bytes'] );
		self::assertGreaterThan( 0, $logger->stats()['files'] );
		self::assertLessThan( 50, $logger->stats()['files'] );
	}

	/**
	 * Verify busy storage drops event without blocking or throwing.
	 *
	 * @return void
	 */
	public function test_busy_storage_drops_event_without_blocking_or_throwing(): void {
		$logger = $this->logger();
		$result = $logger->with_lock( fn(): bool => $logger->log( 'info', 'system', 'plugin.boot' ) );
		self::assertFalse( $result );
	}

	/**
	 * Verify export reinspects persisted records and enforces exact range.
	 *
	 * @return void
	 */
	public function test_export_reinspects_persisted_records_and_enforces_exact_range(): void {
		if ( ! class_exists( '\ZipArchive' ) ) {
			self::markTestSkipped( 'PHP ZIP extension is required for export tests.' );
		}
		$logger     = $this->logger();
		$this->now -= 3700;
		$logger->log( 'info', 'system', 'plugin.boot' );
		$this->now += 3700;
		$logger->log( 'info', 'system', 'plugin.started', array( 'count' => 3 ) );
		$files = $logger->files();
		file_put_contents(
			end( $files ),
			json_encode(
				array(
					'timestamp' => gmdate( 'Y-m-d\TH:i:s\Z', $this->now ),
					'level'     => 'info',
					'category'  => 'admin',
					'event'     => 'sk_live_secret',
					'context'   => array(
						'password'  => 'SECRET',
						'api_token' => 'SECRET',
						'count'     => 4,
					),
					'Cookie'    => 'SECRET',
				)
			) . "\n",
			FILE_APPEND
		);
		$path = ( new Exporter( $logger ) )->build(
			1,
			array(
				'version'           => '1.0.0-dev',
				'channel'           => 'dev',
				'commit'            => str_repeat( 'a', 40 ),
				'php_version'       => '8.3.6',
				'wordpress_version' => '7.1.4',
				'host'              => 'PRIVATE',
				'password'          => 'SECRET',
			)
		);
		$zip  = new \ZipArchive();
		self::assertTrue( $zip->open( $path ) );
		$manifest = json_decode( $zip->getFromName( 'manifest.json' ), true, 8, JSON_THROW_ON_ERROR );
		self::assertSame( 2, $manifest['records'] );
		self::assertSame( 1, $manifest['range_hours'] );
		self::assertFalse( $manifest['truncated'] );
		self::assertSame( str_repeat( 'a', 40 ), $manifest['build']['commit'] );
		$all = '';
		for ( $i = 0; $i < $zip->numFiles; ++$i ) { // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Native ZipArchive API.
			$all .= $zip->getFromIndex( $i );
		}
		self::assertStringNotContainsString( 'SECRET', $all );
		self::assertStringNotContainsString( 'PRIVATE', $all );
		self::assertStringNotContainsString( 'sk_live_secret', $all );
		foreach ( $manifest['entries'] as $entry ) {
			self::assertSame( $entry['sha256'], hash( 'sha256', $zip->getFromName( $entry['path'] ) ) );
		}
		$zip->close();
		self::assertSame( 0600, fileperms( $path ) & 0777 );
	}


	/**
	 * Verify storage faults cannot expose paths through warnings.
	 *
	 * @return void
	 */
	public function test_storage_faults_do_not_emit_unsuppressed_warnings(): void {
		$logger = $this->logger();
		rmdir( $logger->directory() );
		file_put_contents( $logger->directory(), 'not a directory' );
		$warnings = array();
		set_error_handler( // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_set_error_handler -- Fault-injection test captures only unsuppressed warnings.
			static function ( int $severity, string $message ) use ( &$warnings ): bool {
				if ( error_reporting() & $severity ) { // phpcs:ignore WordPress.PHP.DevelopmentFunctions.prevent_path_disclosure_error_reporting,WordPress.PHP.DiscouragedPHPFunctions.runtime_configuration_error_reporting -- Observe the suppression mask without changing configuration.
					$warnings[] = $message;
				}
				return true;
			}
		);
		try {
			self::assertFalse( $logger->log( 'error', 'system', 'internal.error' ) );
			try {
				new Logger( $logger->directory() . '/child', array( $this->base . '/web' ) );
				self::fail( 'Invalid directory creation succeeded.' );
			} catch ( \RuntimeException $error ) {
				self::assertStringNotContainsString( $this->base, $error->getMessage() );
			}
		} finally {
			restore_error_handler();
		}
		self::assertSame( array(), $warnings );
	}

	/**
	 * Verify active downloads survive capacity pressure without quota overflow.
	 *
	 * @return void
	 */
	public function test_fresh_export_is_leased_during_quota_pressure(): void {
		if ( ! class_exists( '\ZipArchive' ) ) {
			self::markTestSkipped( 'PHP ZIP extension is required.' );
		}
		$logger = $this->logger( true, array(), 524288 );
		$logger->log( 'info', 'system', 'plugin.boot' );
		$exporter = new Exporter( $logger );
		$path     = $exporter->build( 1, array( 'version' => '1.0.0-dev' ) );
		$lease    = $logger->directory() . '/export-' . str_repeat( '0', 32 ) . '.zip';
		file_put_contents( $lease, str_repeat( 'x', 450560 ) );
		touch( $lease, $this->now );
		for ( $i = 0; $i < 1000; ++$i ) {
			$logger->log( 'info', 'system', 'plugin.boot', array( 'count' => $i ) );
		}
		self::assertFileExists( $path );
		self::assertLessThanOrEqual( 524288, $logger->stats()['size_bytes'] );
		$this->expectException( \RuntimeException::class );
		$exporter->build( 1, array() );
	}


	/**
	 * Verify a custom tiny quota rejects export without deleting its input.
	 *
	 * @return void
	 */
	public function test_tiny_export_quota_preserves_retained_input(): void {
		if ( ! class_exists( '\ZipArchive' ) ) {
			self::markTestSkipped( 'PHP ZIP extension is required.' );
		}
		$logger = $this->logger( true, array(), 131072 );
		self::assertTrue( $logger->log( 'info', 'system', 'plugin.boot' ) );
		$input  = $logger->files()[0];
		$before = file_get_contents( $input );
		try {
			( new Exporter( $logger ) )->build( 1, array() );
			self::fail( 'A quota too small to preserve logs was accepted.' );
		} catch ( \RuntimeException $error ) {
			self::assertStringContainsString( '512 KiB', $error->getMessage() );
		}
		self::assertSame( $before, file_get_contents( $input ) );
		self::assertCount( 1, $logger->files() );
	}

	/**
	 * Verify a supported smaller quota exports the retained record.
	 *
	 * @return void
	 */
	public function test_small_supported_export_quota_includes_input_records(): void {
		if ( ! class_exists( '\ZipArchive' ) ) {
			self::markTestSkipped( 'PHP ZIP extension is required.' );
		}
		$logger = $this->logger( true, array(), 524288 );
		self::assertTrue( $logger->log( 'info', 'system', 'plugin.boot' ) );
		$input  = $logger->files()[0];
		$before = file_get_contents( $input );
		$path   = ( new Exporter( $logger ) )->build( 1, array() );
		$zip    = new \ZipArchive();
		self::assertTrue( $zip->open( $path ) );
		$manifest = json_decode( $zip->getFromName( 'manifest.json' ), true, 8, JSON_THROW_ON_ERROR );
		self::assertSame( 1, $manifest['records'] );
		self::assertFalse( $manifest['truncated'] );
		$zip->close();
		self::assertSame( $before, file_get_contents( $input ) );
	}

	/**
	 * Verify export rejects unrecognized time window.
	 *
	 * @return void
	 */
	public function test_export_rejects_unrecognized_time_window(): void {
		$this->expectException( \InvalidArgumentException::class );
		( new Exporter( $this->logger() ) )->build( 48, array() );
	}
}
