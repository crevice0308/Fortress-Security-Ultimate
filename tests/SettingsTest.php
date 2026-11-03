<?php
/**
 * Settings boundary regression tests.
 *
 * @package FortressSecurityUltimate
 */

namespace Fortress\Security\Tests;

require_once __DIR__ . '/Support/wordpress-functions.php';

use Fortress\Security\Plugin;
use Fortress\Security\Settings;
use PHPUnit\Framework\TestCase;

/** Bounded input and recovery tests. */
final class SettingsTest extends TestCase {
	/**
	 * Isolated WordPress option store.
	 *
	 * @var array<string,mixed>
	 */
	public static array $options = array();

	/** Prepare each case. */
	protected function setUp(): void {
		self::$options = array();
		if ( ! defined( 'FSU_VERSION' ) ) {
			define( 'FSU_VERSION', '1.0.0-dev.2' );
		}
		if ( ! defined( 'FSU_DIR' ) ) {
			define( 'FSU_DIR', dirname( __DIR__ ) . '/' );
		}
	}

	/** Unknown fields and type confusion never persist. */
	public function test_sanitization_rejects_untrusted_fields(): void {
		$result = Settings::sanitize(
			array(
				'debug'          => array( 'yes' ),
				'capture_errors' => 'true',
				'categories'     => array( 'audit', 'http', array( 'php' ), 'audit' ),
				'token'          => 'secret',
				'directory'      => '/tmp/evil',
			)
		);
		self::assertSame( array( 'debug', 'capture_errors', 'categories' ), array_keys( $result ) );
		self::assertFalse( $result['debug'] );
		self::assertFalse( $result['capture_errors'] );
		self::assertSame( array( 'audit', 'internal', 'admin', 'system' ), $result['categories'] );
	}

	/** Saving can be reversed without touching unrelated site data. */
	public function test_save_and_one_click_restore(): void {
		self::$options['unrelated'] = 'preserved';
		$original                   = Settings::get();
		Settings::save(
			array(
				'debug'          => false,
				'capture_errors' => false,
				'categories'     => array( 'audit' ),
			)
		);
		self::assertFalse( Settings::get()['debug'] );
		Settings::restore();
		self::assertSame( $original, Settings::get() );
		self::assertSame( 'preserved', self::$options['unrelated'] );
	}

	/** Corrupted stored values restore safe defaults. */
	public function test_invalid_persisted_settings_use_defaults(): void {
		self::$options['fsu_settings'] = 'corrupted';
		self::assertSame( Settings::defaults(), Settings::get() );
	}

	/** A third-party handler remains installed with its original semantics. */
	public function test_existing_error_handler_is_not_wrapped(): void {
		$handler = static fn(): mixed => null;
		// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_set_error_handler -- Error-handler preservation regression test.
		set_error_handler( $handler, E_USER_WARNING );
		try {
			$method = new \ReflectionMethod( Plugin::class, 'capture_errors' );
			$method->invoke( null );
			// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_set_error_handler -- Read the active handler for this regression test.
			$current = set_error_handler( static fn(): bool => false );
			restore_error_handler();
			self::assertSame( $handler, $current );
		} finally {
			restore_error_handler();
		}
	}

	/** WordPress hooks use registered machine-readable identifiers. */
	public function test_wordpress_error_event_is_preserved(): void {
		$directory = sys_get_temp_dir() . '/fsu-hook-test-' . bin2hex( random_bytes( 8 ) );
		$logger    = new \Fortress\Security\Log\Logger( $directory );
		$property  = new \ReflectionProperty( Plugin::class, 'logger' );
		$previous  = $property->getValue();
		$handler   = static fn(): bool => false;
		// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_set_error_handler -- Preserve the test runner handler.
		set_error_handler( $handler );
		try {
			$property->setValue( null, $logger );
			( new \ReflectionMethod( Plugin::class, 'capture_errors' ) )->invoke( null );
			$GLOBALS['fsu_test_actions']['wp_error_added']();
			$file = $logger->files()[0];
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Read the isolated log fixture.
			$record = json_decode( file_get_contents( $file ), true );
			// phpcs:ignore WordPress.WP.CapitalPDangit.MisspelledInText -- Assert exact machine-readable identifiers.
			self::assertSame( 'wordpress', $record['category'] );
			// phpcs:ignore WordPress.WP.CapitalPDangit.MisspelledInText -- Assert exact machine-readable identifiers.
			self::assertSame( 'wordpress.error', $record['event'] );
		} finally {
			$property->setValue( null, $previous );
			restore_error_handler();
			foreach ( glob( $directory . '/*' ) as $file ) {
				// phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- Delete isolated test fixture.
				unlink( $file );
			}
			// phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- Delete isolated test lock.
			unlink( $directory . '/.lock' );
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_rmdir -- Delete isolated fixture directory.
			rmdir( $directory );
		}
	}
}
