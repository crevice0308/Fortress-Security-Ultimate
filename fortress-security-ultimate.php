<?php
/**
 * Plugin Name: Fortress Security Ultimate
 * Description: 日本語セキュリティ診断と保護された開発者ログ。Phase 1 開発版。
 * Version: 1.0.0-dev.2
 * Requires at least: 7.0
 * Requires PHP: 8.2
 * Author: Asterion Labs
 * Text Domain: fortress-security-ultimate
 * Domain Path: /languages
 * License: GPL-2.0-or-later
 * Update URI: https://example.invalid/fortress-security-ultimate
 *
 * @package FortressSecurityUltimate
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'FSU_VERSION', '1.0.0-dev.2' );
define( 'FSU_FILE', __FILE__ );
define( 'FSU_DIR', __DIR__ . '/' );
require_once FSU_DIR . 'src/autoload.php';

register_activation_hook( __FILE__, array( Fortress\Security\Plugin::class, 'activate' ) );
register_deactivation_hook( __FILE__, array( Fortress\Security\Plugin::class, 'deactivate' ) );
add_action( 'plugins_loaded', array( Fortress\Security\Plugin::class, 'boot' ) );
