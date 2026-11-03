<?php
/**
 * Constant declarations for static analysis, without loading WordPress.
 *
 * @package FortressSecurityUltimate
 */

defined( 'FSU_VERSION' ) || define( 'FSU_VERSION', '1.0.0-dev.2' );
defined( 'FSU_FILE' ) || define( 'FSU_FILE', dirname( __DIR__ ) . '/fortress-security-ultimate.php' );
defined( 'FSU_DIR' ) || define( 'FSU_DIR', dirname( __DIR__ ) . '/' );
defined( 'FSU_SAFE_MODE' ) || define( 'FSU_SAFE_MODE', false );
defined( 'FSU_PRIVATE_DIR' ) || define( 'FSU_PRIVATE_DIR', '/private/fsu' );
defined( 'ABSPATH' ) || define( 'ABSPATH', '/wordpress/' );
defined( 'HOUR_IN_SECONDS' ) || define( 'HOUR_IN_SECONDS', 3600 );
