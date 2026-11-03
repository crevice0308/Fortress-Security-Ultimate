<?php
/**
 * Collect only metadata needed for read-only diagnostics.
 *
 * @package FortressSecurityUltimate
 */

namespace Fortress\Security\Audit;

/**
 * WordPress boundary; does not read configuration file contents or request data.
 */
final class Environment {

	/**
	 * Collect safe, non-identifying environment metadata.
	 *
	 * @param bool $logs_ready Whether the private log store initialized.
	 * @return array<string,mixed>
	 */
	public static function collect( bool $logs_ready ): array {
		global $wp_version;

		$config = null;
		if ( defined( 'ABSPATH' ) ) {
			$root = rtrim( ABSPATH, '/\\' );
			// Suppress metadata warnings that could disclose private paths; false means unknown.
			// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Checked metadata result; never display filesystem paths.
			if ( @is_file( $root . '/wp-config.php' ) ) {
				$config = $root . '/wp-config.php';
				// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Checked metadata result; never display filesystem paths.
			} elseif ( @is_file( dirname( $root ) . '/wp-config.php' ) && ! @is_file( dirname( $root ) . '/wp-settings.php' ) ) {
				$config = dirname( $root ) . '/wp-config.php';
			}
		}

		return array(
			'php_version'         => PHP_VERSION,
			'wp_version'          => is_string( $wp_version ) ? $wp_version : null,
			'https'               => function_exists( 'is_ssl' ) ? is_ssl() : null,
			'debug_display'       => defined( 'WP_DEBUG' ) && WP_DEBUG && ( ! defined( 'WP_DEBUG_DISPLAY' ) || WP_DEBUG_DISPLAY ),
			'file_edit_disabled'  => defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT,
			'expose_php'          => self::ini_boolean( 'expose_php' ),
			'display_errors'      => self::ini_boolean( 'display_errors' ),
			'allow_url_include'   => self::ini_boolean( 'allow_url_include' ),
			'config_permissions'  => self::permission_bits( $config ),
			'content_permissions' => self::permission_bits( defined( 'WP_CONTENT_DIR' ) ? WP_CONTENT_DIR : null ),
			'zip_available'       => class_exists( '\ZipArchive' ),
			'logs_ready'          => $logs_ready,
			'extensions'          => array(
				'json'    => extension_loaded( 'json' ),
				'openssl' => extension_loaded( 'openssl' ),
				'sodium'  => extension_loaded( 'sodium' ),
			),
		);
	}

	/**
	 * PHP settings have several valid representations, including "stderr".
	 *
	 * @param string $name Known INI setting name.
	 * @return bool|null
	 */
	private static function ini_boolean( string $name ): ?bool {
		$value = ini_get( $name );
		if ( false === $value ) {
			return null;
		}
		$normalized = strtolower( trim( $value ) );
		if ( in_array( $normalized, array( '', '0', 'off', 'false', 'none' ), true ) ) {
			return false;
		}
		if ( in_array( $normalized, array( '1', 'on', 'true', 'yes', 'stderr', 'stdout' ), true ) ) {
			return true;
		}
		return null;
	}

	/**
	 * Read Unix permission metadata only; do not read the file.
	 *
	 * @param string|null $path Private internal path; never returned or logged.
	 * @return int|null
	 */
	private static function permission_bits( ?string $path ): ?int {
		// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Failed metadata lookup is returned as unknown, without paths.
		if ( null === $path || '\\' === DIRECTORY_SEPARATOR || ! @file_exists( $path ) ) {
			return null;
		}
		// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- A race or access restriction returns false, not a path-bearing warning.
		$bits = @fileperms( $path );
		return false === $bits ? null : $bits & 07777;
	}
}
