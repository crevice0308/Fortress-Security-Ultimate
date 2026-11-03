<?php
/**
 * Composition root with no front-end network requests or file scans.
 *
 * @package FortressSecurityUltimate
 */

namespace Fortress\Security;

use Fortress\Security\Admin\Dashboard;
use Fortress\Security\Log\Logger;

/** WordPress lifecycle. */
final class Plugin {
	/**
	 * Runtime logger, absent when storage is unavailable.
	 *
	 * @var Logger|null
	 */
	private static ?Logger $logger = null;

	/** Install only on supported, single-site WordPress. */
	public static function activate(): void {
		global $wp_version;
		if ( is_multisite() || version_compare( PHP_VERSION, '8.2', '<' ) || version_compare( $wp_version, '7.0', '<' ) ) {
			wp_die( esc_html__( 'Phase 1 は WordPress 7.0 以上、PHP 8.2 以上のシングルサイト用です。', 'fortress-security-ultimate' ) );
		}
		add_option( 'fsu_settings', Settings::defaults(), '', false );
		if ( ! wp_next_scheduled( 'fsu_prune_logs' ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'hourly', 'fsu_prune_logs' );
		}
	}

	/** Keep logs/settings for investigation; only unschedule work. */
	public static function deactivate(): void {
		wp_clear_scheduled_hook( 'fsu_prune_logs' );
	}

	/** Wire dependencies. No public API is exposed by Phase 1. */
	public static function boot(): void {
		if ( is_multisite() ) {
			return;
		}
		$started  = hrtime( true );
		$settings = Settings::get();
		try {
			$root         = defined( 'FSU_PRIVATE_DIR' ) ? FSU_PRIVATE_DIR : rtrim( sys_get_temp_dir(), '/\\' ) . '/fsu-' . substr( hash( 'sha256', ABSPATH ), 0, 24 );
			$public_roots = array( ABSPATH );
			if ( ! empty( $_SERVER['DOCUMENT_ROOT'] ) && is_string( $_SERVER['DOCUMENT_ROOT'] ) ) {
				// phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- Server-supplied filesystem path is canonicalized by Logger, never logged or output.
				$public_roots[] = $_SERVER['DOCUMENT_ROOT'];
			}
			self::$logger = new Logger( $root, $public_roots, $settings['debug'], $settings['categories'] );
		} catch ( \Throwable $error ) {
			// A storage failure must not break site rendering. Do not expose paths/messages.
			self::$logger = null;
		}
		( new Dashboard( self::$logger ) )->register();
		add_action( 'fsu_prune_logs', array( self::class, 'prune' ) );
		if ( ! Settings::safe_mode() && $settings['capture_errors'] && null !== self::$logger ) {
			self::capture_errors();
		}
		if ( ! Settings::safe_mode() && $settings['debug'] && in_array( 'performance', $settings['categories'], true ) && null !== self::$logger ) {
			register_shutdown_function(
				static function () use ( $started ): void {
					self::$logger?->log(
						'Debug',
						'performance',
						'performance.request',
						array(
							'duration_ms'  => ( hrtime( true ) - $started ) / 1000000,
							'memory_bytes' => memory_get_peak_usage( true ),
						)
					);
				}
			);
		}
	}

	/** Cron pruning is bounded and never breaks cron on disk errors. */
	public static function prune(): void {
		if ( null !== self::$logger && ! Settings::safe_mode() ) {
			try {
				self::$logger->prune();
			} catch ( \Throwable $error ) {
				// Logger will retry on the next write or hourly cron.
				return;
			}
		}
	}

	/** Record error metadata only; preserve existing handlers and PHP reporting. */
	private static function capture_errors(): void {
		// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_set_error_handler -- Implements opt-in metadata-only error capture.
		$previous = set_error_handler(
			static function ( int $type, string $message, string $file, int $line ): bool {
				// phpcs:ignore WordPress.PHP.DevelopmentFunctions.prevent_path_disclosure_error_reporting,WordPress.PHP.DiscouragedPHPFunctions.runtime_configuration_error_reporting -- Reads current mask; does not change it or expose error text.
				if ( ( error_reporting() & $type ) && str_starts_with( $file, FSU_DIR ) ) {
					self::$logger?->log(
						'Error',
						'php',
						'php.error',
						array(
							'error_type' => $type,
							'line'       => $line,
						)
					);
				}
				return false;
			}
		);
		// Preserve an existing handler and its unknown error-level mask without wrapping it.
		if ( null !== $previous ) {
			restore_error_handler();
		}
		register_shutdown_function(
			static function (): void {
				$error = error_get_last();
				if ( null !== $error && in_array( $error['type'], array( E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR ), true ) ) {
					self::$logger?->log( 'Error', 'php', 'php.fatal', array( 'error_type' => $error['type'] ) );
				}
			}
		);
		add_action(
			'wp_error_added',
			static function (): void {
				// phpcs:ignore WordPress.WP.CapitalPDangit.MisspelledInText -- Fixed machine-readable category and event codes.
				self::$logger?->log( 'Error', 'wordpress', 'wordpress.error' );
			}
		);
	}
}
