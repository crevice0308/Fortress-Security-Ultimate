<?php
/**
 * Runtime autoloader; no Composer dependency on production sites.
 *
 * @package FortressSecurityUltimate
 */

spl_autoload_register(
	static function ( string $class_name ): void {
		$prefix = 'Fortress\\Security\\';
		if ( ! str_starts_with( $class_name, $prefix ) ) {
			return;
		}
		$relative = substr( $class_name, strlen( $prefix ) );
		if ( ! preg_match( '/\A[A-Za-z][A-Za-z0-9]*(?:\\\\[A-Za-z][A-Za-z0-9]*)*\z/', $relative ) ) {
			return;
		}
		$file = __DIR__ . '/' . str_replace( '\\', '/', $relative ) . '.php';
		if ( is_file( $file ) ) {
			require_once $file;
		}
	}
);
