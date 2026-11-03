<?php
/**
 * Central authenticated mutation guard.
 *
 * @package FortressSecurityUltimate
 */

namespace Fortress\Security\Admin;

/** Authorize every state change and export independently. */
final class Access {
	/**
	 * Enforce method, capability and per-action CSRF token.
	 *
	 * @param string $action Fixed action identifier.
	 */
	public static function authorize( string $action ): void {
		if ( ! in_array( $action, array( 'save', 'restore', 'export' ), true ) ) {
			wp_die( esc_html__( '操作が無効です。', 'fortress-security-ultimate' ), '', array( 'response' => 400 ) );
		}
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- Method is validated by an exact comparison, never persisted or output.
		if ( 'POST' !== ( $_SERVER['REQUEST_METHOD'] ?? '' ) || ! current_user_can( 'manage_options' ) || is_multisite() ) {
			wp_die( esc_html__( 'この操作を実行する権限がありません。', 'fortress-security-ultimate' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'fsu_' . $action );
	}
}
