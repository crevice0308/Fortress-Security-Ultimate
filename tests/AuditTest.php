<?php
/**
 * Read-only environment diagnostic tests.
 *
 * @package FortressSecurityUltimate
 */

use Fortress\Security\Audit\Environment;
use Fortress\Security\Audit\Inspector;
use PHPUnit\Framework\TestCase;

/**
 * Diagnose unsafe and unknown inputs without I/O or leaking their values.
 */
final class AuditTest extends TestCase {

	/**
	 * Provide a supported environment snapshot.
	 *
	 * @return array<string,mixed>
	 */
	private function environment(): array {
		return array(
			'php_version'         => '8.4.27',
			'wp_version'          => '7.1.4',
			'https'               => true,
			'debug_display'       => false,
			'file_edit_disabled'  => true,
			'expose_php'          => false,
			'display_errors'      => false,
			'allow_url_include'   => false,
			'config_permissions'  => 0640,
			'content_permissions' => 0755,
			'zip_available'       => true,
			'logs_ready'          => true,
			'extensions'          => array(
				'json'    => true,
				'openssl' => true,
				'sodium'  => true,
			),
		);
	}

	/**
	 * Index diagnostic rows for assertions.
	 *
	 * @param array<string,mixed> $environment Input snapshot.
	 * @return array<string,array<string,string>>
	 */
	private function rows( array $environment ): array {
		return array_column( ( new Inspector() )->inspect( $environment ), null, 'id' );
	}

	/** Supported settings still include an explicit scope limitation. */
	public function test_supported_environment_has_only_pass_and_scope_information(): void {
		$rows = $this->rows( $this->environment() );
		self::assertCount( 16, $rows );
		foreach ( $rows as $id => $row ) {
			self::assertSame( 'audit_scope' === $id ? 'info' : 'pass', $row['status'], $id );
		}
		self::assertStringContainsString( '未実装', $rows['audit_scope']['detail'] );
	}

	/** Missing inputs cannot accidentally pass. */
	public function test_missing_inputs_never_become_a_positive_verdict(): void {
		foreach ( $this->rows( array() ) as $row ) {
			self::assertSame( 'info', $row['status'], $row['id'] );
		}
	}

	/** Boolean strings are untrusted rather than loosely coerced. */
	public function test_boolean_strings_are_unknown_instead_of_coerced(): void {
		$env                      = $this->environment();
		$env['https']             = 'true';
		$env['allow_url_include'] = 'false';
		$rows                     = $this->rows( $env );
		self::assertSame( 'info', $rows['https']['status'] );
		self::assertSame( 'info', $rows['allow_url_include']['status'] );
	}

	/** Diagnostic checks do not modify unsafe source settings. */
	public function test_unsafe_configuration_is_reported_without_mutation(): void {
		$env                        = $this->environment();
		$env['allow_url_include']   = true;
		$env['display_errors']      = true;
		$env['config_permissions']  = 0666;
		$env['content_permissions'] = 0777;
		$copy                       = $env;
		$rows                       = $this->rows( $env );
		self::assertSame( 'error', $rows['allow_url_include']['status'] );
		self::assertSame( 'warning', $rows['display_errors']['status'] );
		self::assertSame( 'error', $rows['config_permissions']['status'] );
		self::assertSame( 'error', $rows['content_permissions']['status'] );
		self::assertSame( $copy, $env );
	}

	/** Permission findings distinguish shared reads from world writes. */
	public function test_permission_review_distinguishes_shared_reads_and_writes(): void {
		$env                        = $this->environment();
		$env['config_permissions']  = 0644;
		$env['content_permissions'] = 0775;
		$rows                       = $this->rows( $env );
		self::assertSame( 'warning', $rows['config_permissions']['status'] );
		self::assertSame( 'warning', $rows['content_permissions']['status'] );
		$env['config_permissions'] = '0640';
		self::assertSame( 'info', $this->rows( $env )['config_permissions']['status'] );
	}

	/** Version policy is deliberately bounded to the development targets. */
	public function test_version_policy_is_bounded_and_does_not_claim_cve_safety(): void {
		$env                = $this->environment();
		$env['php_version'] = '8.1.99';
		self::assertSame( 'error', $this->rows( $env )['php_version']['status'] );
		$env['php_version'] = '8.2.35';
		self::assertSame( 'warning', $this->rows( $env )['php_version']['status'] );
		$env['php_version'] = '8.6.0';
		self::assertSame( 'info', $this->rows( $env )['php_version']['status'] );
		$env['wp_version'] = '6.9.9';
		self::assertSame( 'warning', $this->rows( $env )['wp_version']['status'] );
		$env['wp_version'] = '7.2.0';
		self::assertSame( 'info', $this->rows( $env )['wp_version']['status'] );
	}

	/** Reports do not echo untrusted values or unrelated sensitive inputs. */
	public function test_untrusted_values_and_identifiers_never_enter_report(): void {
		$env                            = $this->environment();
		$env['php_version']             = '<script>alert(1)</script>';
		$env['wp_version']              = '7.1.4 <script>';
		$env['api_token']               = 'secret-do-not-echo';
		$env['extensions']['arbitrary'] = 'customer@example.com';
		// phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Pure unit test deliberately has no WordPress dependency.
		$json = json_encode( ( new Inspector() )->inspect( $env ) );
		self::assertIsString( $json );
		self::assertStringNotContainsString( '<script>', $json );
		self::assertStringNotContainsString( 'secret-do-not-echo', $json );
		self::assertStringNotContainsString( 'customer@example.com', $json );
		self::assertSame( 'info', $this->rows( $env )['php_version']['status'] );
	}

	/** Prereleases do not inherit the stable release verdict. */
	public function test_prereleases_are_not_treated_as_supported_stable_releases(): void {
		$env                = $this->environment();
		$env['php_version'] = '8.5.0RC1';
		$env['wp_version']  = '7.1-beta2';
		$rows               = $this->rows( $env );
		self::assertSame( 'info', $rows['php_version']['status'] );
		self::assertSame( 'info', $rows['wp_version']['status'] );
	}

	/** The collected snapshot excludes private paths and request values. */
	public function test_collection_has_no_paths_domains_or_request_values(): void {
		$metadata = Environment::collect( false );
		self::assertSame( PHP_VERSION, $metadata['php_version'] );
		self::assertFalse( $metadata['logs_ready'] );
		self::assertSame( array( 'json', 'openssl', 'sodium' ), array_keys( $metadata['extensions'] ) );
		foreach ( $metadata as $key => $value ) {
			self::assertStringNotContainsString( 'path', $key );
			self::assertStringNotContainsString( 'token', $key );
		}
	}
}
