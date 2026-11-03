<?php
/**
 * Failure-path privacy and archive delivery regression tests.
 *
 * @package FortressSecurityUltimate
 */

namespace Fortress\Security\Tests;

use Fortress\Security\Admin\ZipDownload;
use PHPUnit\Framework\TestCase;

/** Protect the response from private paths and incomplete archives. */
final class ZipDownloadTest extends TestCase {
	/**
	 * Local disposable directory.
	 *
	 * @var string
	 */
	private string $directory;

	/** Set up an isolated fixture directory. */
	protected function setUp(): void {
		$this->directory = sys_get_temp_dir() . '/fsu-download-test-' . bin2hex( random_bytes( 8 ) );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_mkdir -- Isolated native fixture without WordPress dependency.
		mkdir( $this->directory, 0700 );
	}

	/** Delete disposable fixtures. */
	protected function tearDown(): void {
		foreach ( glob( $this->directory . '/*' ) as $path ) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- Isolated fixture cleanup.
			unlink( $path );
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_rmdir -- Isolated fixture cleanup.
		rmdir( $this->directory );
	}

	/** The original bytes and expected length are preserved. */
	public function test_complete_binary_delivery(): void {
		$path = $this->directory . '/archive.zip';
		$zip  = new \ZipArchive();
		$zip->open( $path, \ZipArchive::CREATE );
		$zip->addFromString( 'manifest.json', '{"schema":1}' );
		$zip->close();
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Read an isolated binary fixture.
		$expected = file_get_contents( $path );
		$download = ZipDownload::open( $path );
		ob_start();
		$sent = ZipDownload::send( $download['stream'], $download['size'] );
		$body = ob_get_clean();
		ZipDownload::cleanup( $download['stream'], $path );
		self::assertTrue( $sent );
		self::assertSame( $expected, $body );
		self::assertFileDoesNotExist( $path );
	}

	/** Missing files are rejected before a success response can be sent. */
	public function test_missing_file_has_no_path_or_unsuppressed_warning(): void {
		$warnings = array();
		// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_set_error_handler -- Observe only unsuppressed warnings in this regression.
		set_error_handler(
			static function ( int $severity, string $message ) use ( &$warnings ): bool {
			// phpcs:ignore WordPress.PHP.DevelopmentFunctions.prevent_path_disclosure_error_reporting,WordPress.PHP.DiscouragedPHPFunctions.runtime_configuration_error_reporting -- Read the error mask without changing it.
				if ( error_reporting() & $severity ) {
					$warnings[] = $message;
				}
				return true;
			}
		);
		try {
			try {
				ZipDownload::open( $this->directory . '/missing.zip' );
				self::fail( 'Missing archive was accepted.' );
			} catch ( \RuntimeException $error ) {
				self::assertStringNotContainsString( $this->directory, $error->getMessage() );
			}
			ZipDownload::cleanup( null, $this->directory . '/missing.zip' );
			self::assertSame( array(), $warnings );
		} finally {
			restore_error_handler();
		}
	}

	/** A truncated descriptor is reported without adding diagnostic text to bytes. */
	public function test_short_read_is_detected(): void {
		$path = $this->directory . '/archive.zip';
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Isolated native fixture without WordPress dependency.
		file_put_contents( $path, 'archive-bytes' );
		$download = ZipDownload::open( $path );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- Isolated native fixture without WordPress dependency.
		$writer = fopen( $path, 'wb' );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Isolated native fixture without WordPress dependency.
		fclose( $writer );
		ob_start();
		$sent = ZipDownload::send( $download['stream'], $download['size'] );
		$body = ob_get_clean();
		ZipDownload::cleanup( $download['stream'], $path );
		self::assertFalse( $sent );
		self::assertSame( '', $body );
	}

	/** Symlinks cannot turn a generated-archive delivery into a different file. */
	public function test_symlink_is_rejected(): void {
		$target = $this->directory . '/target.zip';
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Isolated native fixture without WordPress dependency.
		file_put_contents( $target, 'private-data' );
		symlink( $target, $this->directory . '/link.zip' );
		$this->expectException( \RuntimeException::class );
		ZipDownload::open( $this->directory . '/link.zip' );
	}
}
