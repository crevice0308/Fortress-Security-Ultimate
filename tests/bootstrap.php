<?php
/**
 * Isolated unit-test autoloading; no WordPress installation is simulated here.
 *
 * @package FortressSecurityUltimate
 */

if ( is_file( dirname( __DIR__ ) . '/vendor/autoload.php' ) ) {
	require_once dirname( __DIR__ ) . '/vendor/autoload.php';
} else {
	spl_autoload_register(
		static function ( string $class_name ): void {
			$prefix = 'Fortress\\Security\\';
			if ( str_starts_with( $class_name, $prefix ) ) {
				$path = dirname( __DIR__ ) . '/src/' . str_replace( '\\', '/', substr( $class_name, strlen( $prefix ) ) ) . '.php';
				if ( is_file( $path ) ) {
					require_once $path;
				}
			}
		}
	);
}
