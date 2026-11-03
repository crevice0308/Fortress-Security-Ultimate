<?php
/**
 * Settings boundary regression tests with isolated option storage.
 *
 * @package FortressSecurityUltimate
 */

namespace Fortress\Security;

/**
 * Test-only stand-in for options.
 *
 * @param string $name Name.
 * @param mixed  $fallback Default.
 */
function get_option( string $name, mixed $fallback = false ): mixed {
	return \Fortress\Security\Tests\SettingsTest::$options[ $name ] ?? $fallback;
}

/**
 * Test-only option writer.
 *
 * @param string $name Name.
 * @param mixed  $value Value.
 * @param bool   $autoload Ignored test argument.
 */
function update_option( string $name, mixed $value, bool $autoload = false ): bool {
	\Fortress\Security\Tests\SettingsTest::$options[ $name ] = $value;
	return ! $autoload;
}

/**
 * Test-only action registration used when inspecting error-handler integration.
 *
 * @param string $hook Name.
 * @param mixed  $callback Callback.
 */
function add_action( string $hook, mixed $callback ): bool {
	$GLOBALS['fsu_test_actions'][ $hook ] = $callback;
	return true;
}
