<?php
/**
 * Bounded settings and rollback, with no stored credentials.
 *
 * @package FortressSecurityUltimate
 */

namespace Fortress\Security;

/** Settings API boundary. */
final class Settings {
	/** Supported categories. */
	public const CATEGORIES = array( 'php', 'wordpress', 'internal', 'waf', 'integrity', 'cloudflare', 'license', 'update', 'performance', 'admin', 'audit', 'system' );

	/** Default preferences. */
	public static function defaults(): array {
		return array(
			'debug'          => str_contains( FSU_VERSION, '-' ),
			'capture_errors' => true,
			'categories'     => self::CATEGORIES,
		);
	}

	/**
	 * Keep only recognized scalar/enum fields.
	 *
	 * @param array<string,mixed> $input Untrusted settings.
	 */
	public static function sanitize( array $input ): array {
		$categories = isset( $input['categories'] ) && is_array( $input['categories'] ) ? $input['categories'] : array();
		$categories = array_values( array_filter( self::CATEGORIES, static fn( string $category ): bool => in_array( $category, $categories, true ) ) );
		// Internal operational/security events remain available regardless of debug preferences.
		$categories = array_values( array_unique( array_merge( $categories, array( 'internal', 'admin', 'system' ) ) ) );
		return array(
			'debug'          => true === ( $input['debug'] ?? false ) || '1' === ( $input['debug'] ?? false ),
			'capture_errors' => true === ( $input['capture_errors'] ?? false ) || '1' === ( $input['capture_errors'] ?? false ),
			'categories'     => $categories,
		);
	}

	/** Load preferences without autoloading private data. */
	public static function get(): array {
		$value = get_option( 'fsu_settings', self::defaults() );
		return self::sanitize( is_array( $value ) ? $value : self::defaults() );
	}

	/**
	 * Save a single bounded rollback snapshot.
	 *
	 * @param array<string,mixed> $input Untrusted settings.
	 */
	public static function save( array $input ): void {
		update_option( 'fsu_settings_previous', self::get(), false );
		update_option( 'fsu_settings', self::sanitize( $input ), false );
	}

	/** Restore the last saved preferences; never accept uploaded settings. */
	public static function restore(): void {
		$previous = get_option( 'fsu_settings_previous', self::defaults() );
		$current  = self::get();
		update_option( 'fsu_settings', self::sanitize( is_array( $previous ) ? $previous : self::defaults() ), false );
		update_option( 'fsu_settings_previous', $current, false );
	}

	/** Recovery switch controlled only from the server filesystem. */
	public static function safe_mode(): bool {
		return defined( 'FSU_SAFE_MODE' ) && true === FSU_SAFE_MODE;
	}
}
