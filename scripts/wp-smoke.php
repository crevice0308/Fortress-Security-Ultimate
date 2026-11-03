<?php
/**
 * Integration smoke: run through `wp eval-file`, on disposable WordPress only.
 *
 * @package FortressSecurityUltimate
 */

use Fortress\Security\Admin\Access;
use Fortress\Security\Log\Exporter;
use Fortress\Security\Log\Logger;
use Fortress\Security\Settings;

if ( ! defined( 'ABSPATH' ) || ! defined( 'WP_CLI' ) || ! WP_CLI ) {
	throw new RuntimeException( 'Run this through WP-CLI on the isolated test installation.' );
}

/**
 * Enforce an integration assertion.
 *
 * @param bool   $condition Condition to verify.
 * @param string $message   Human-readable assertion.
 * @throws RuntimeException When an integration assertion fails.
 * @return void
 */
function fsu_smoke_assert( bool $condition, string $message ): void {
	if ( ! $condition ) {
		throw new RuntimeException( esc_html( $message ) );
	}
	$GLOBALS['fsu_smoke_assertions'] = ( $GLOBALS['fsu_smoke_assertions'] ?? 0 ) + 1;
	echo 'PASS ' . esc_html( $message ) . "\n";
}

fsu_smoke_assert( 1 === preg_match( '/^1\.0\.0-dev(?:\.[1-9][0-9]{0,2})?$/D', FSU_VERSION ), 'Bounded development channel is retained' );
foreach ( array( 'admin_post_fsu_save', 'admin_post_fsu_restore', 'admin_post_fsu_export' ) as $hook ) {
	fsu_smoke_assert( false !== has_action( $hook ), $hook . ' is registered' );
}

$administrator = get_user_by( 'login', 'fsu-admin' );
fsu_smoke_assert( $administrator instanceof WP_User, 'Disposable administrator exists' );
wp_set_current_user( $administrator->ID );
require_once ABSPATH . 'wp-admin/includes/plugin.php';
do_action( 'admin_menu' );
fsu_smoke_assert( isset( $GLOBALS['_registered_pages']['toplevel_page_fortress-security-ultimate'] ), 'Dedicated administrator menu is registered' );

$original = Settings::get();
Settings::save(
	array(
		'debug'          => false,
		'capture_errors' => false,
		'categories'     => array( 'security', 'admin' ),
	)
);
fsu_smoke_assert( false === Settings::get()['debug'], 'Settings persist through WordPress options' );
Settings::restore();
fsu_smoke_assert( Settings::get() === $original, 'Previous settings restore without changing other options' );

require_once ABSPATH . 'wp-admin/includes/user.php';
$subscriber_id = wp_insert_user(
	array(
		'user_login' => 'fsu-smoke-' . strtolower( wp_generate_password( 12, false, false ) ),
		'user_pass'  => wp_generate_password( 32 ),
		'role'       => 'subscriber',
	)
);
fsu_smoke_assert( is_int( $subscriber_id ) && $subscriber_id > 0, 'Disposable subscriber is created' );

$denial_count = 0;
$handler      = static function () use ( &$denial_count ) {
	return static function () use ( &$denial_count ): void {
		++$denial_count;
		throw new RuntimeException( 'fsu_expected_denial' );
	};
};
// WP-CLI installs its own handler. Run last so a denial becomes an assertion
// instead of terminating the entire smoke process; retain the CLI-specific
// filter for installations or test runners that expose it.
$die_filters = array( 'wp_die_handler', 'wp_die_cli_handler' );
foreach ( $die_filters as $die_filter ) {
	add_filter( $die_filter, $handler, PHP_INT_MAX );
}
$original_method = isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : null;
// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Test harness snapshots caller state without processing request data.
$original_request = $_REQUEST;
// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Test harness snapshots caller state without processing form data.
$original_post      = $_POST;
$subscriber_deleted = false;
try {
	foreach ( array( 'save', 'restore', 'export' ) as $fsu_action ) {
		wp_set_current_user( $administrator->ID );
		$_SERVER['REQUEST_METHOD'] = 'POST';
		$nonce                     = wp_create_nonce( 'fsu_' . $fsu_action );
		$_REQUEST['_wpnonce']      = $nonce;
		$_POST['_wpnonce']         = $nonce;
		Access::authorize( $fsu_action );
		fsu_smoke_assert( true, $fsu_action . ': administrator POST with matching action nonce succeeds' );

		foreach ( array( 'missing_nonce', 'wrong_action_nonce', 'malformed_nonce', 'unauthenticated', 'subscriber', 'GET', 'HEAD' ) as $scenario ) {
			wp_set_current_user( $administrator->ID );
			$_SERVER['REQUEST_METHOD'] = 'POST';
			if ( 'unauthenticated' === $scenario ) {
				wp_set_current_user( 0 );
			} elseif ( 'subscriber' === $scenario ) {
				wp_set_current_user( $subscriber_id );
			} elseif ( in_array( $scenario, array( 'GET', 'HEAD' ), true ) ) {
				$_SERVER['REQUEST_METHOD'] = $scenario;
			}
			// Capability and method checks get a valid nonce for that user, so
			// these cases cannot pass only because nonce validation rejected them.
			$nonce = wp_create_nonce( 'wrong_action_nonce' === $scenario ? 'fsu_unrelated_action' : 'fsu_' . $fsu_action );
			if ( 'malformed_nonce' === $scenario ) {
				$nonce = 'invalid';
			}
			unset( $_REQUEST['_wpnonce'], $_POST['_wpnonce'] );
			if ( 'missing_nonce' !== $scenario ) {
				$_REQUEST['_wpnonce'] = $nonce;
				$_POST['_wpnonce']    = $nonce;
			}
			$denied = false;
			try {
				Access::authorize( $fsu_action );
			} catch ( RuntimeException $exception ) {
				$denied = 'fsu_expected_denial' === $exception->getMessage();
			}
			fsu_smoke_assert( $denied, $fsu_action . ': rejects ' . $scenario );
		}
	}

	wp_set_current_user( $administrator->ID );
	$_SERVER['REQUEST_METHOD'] = 'POST';
	$nonce                     = wp_create_nonce( 'fsu_unknown' );
	$_REQUEST['_wpnonce']      = $nonce;
	$_POST['_wpnonce']         = $nonce;
	$denied                    = false;
	try {
		Access::authorize( 'unknown' );
	} catch ( RuntimeException $exception ) {
		$denied = 'fsu_expected_denial' === $exception->getMessage();
	}
	fsu_smoke_assert( $denied, 'Unknown action is refused despite a matching nonce' );
	fsu_smoke_assert( 22 === $denial_count, 'All 22 expected refusals use the intercepted WordPress die handler' );
} finally {
	foreach ( $die_filters as $die_filter ) {
		remove_filter( $die_filter, $handler, PHP_INT_MAX );
	}
	wp_set_current_user( $administrator->ID );
	$_REQUEST = $original_request;
	$_POST    = $original_post;
	if ( null === $original_method ) {
		unset( $_SERVER['REQUEST_METHOD'] );
	} else {
		$_SERVER['REQUEST_METHOD'] = $original_method;
	}
	$subscriber_deleted = wp_delete_user( $subscriber_id );
}
fsu_smoke_assert( $subscriber_deleted, 'Disposable subscriber is removed after the authorization matrix' );

$logger = new Logger( FSU_PRIVATE_DIR, array( ABSPATH ), true );
fsu_smoke_assert( $logger->log( 'Info', 'admin', 'admin.action', array( 'success' => true ) ), 'Private hourly logger writes an event' );
$exporter = new Exporter( $logger );
$archive  = $exporter->build(
	1,
	array(
		'php_version'       => PHP_VERSION,
		'wordpress_version' => get_bloginfo( 'version' ),
		'version'           => FSU_VERSION,
		'channel'           => 'dev',
	)
);
$zip      = new ZipArchive();
fsu_smoke_assert( true === $zip->open( $archive ), 'Administrator export produces a valid ZIP' );
fsu_smoke_assert( false !== $zip->locateName( 'manifest.json' ), 'Log archive contains machine-readable manifest' );
$zip->close();
// phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- Disposable test export owned by this process.
unlink( $archive );

echo 'Real WordPress Phase 1 smoke passed: ' . (int) $GLOBALS['fsu_smoke_assertions'] . " assertions. No WAF, Stripe, Cloudflare, or vulnerability feed is exercised.\n";
