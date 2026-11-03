<?php
/**
 * Strict metadata projection for local logs and exported logs.
 *
 * @package FortressSecurityUltimate
 */

namespace Fortress\Security\Log;

/** Redactor diagnostic service. */
final class Redactor {
	/**
	 * Diagnostic storage configuration.
	 *
	 * @var array
	 */
	public const CATEGORIES = array( 'system', 'php', 'wordpress', 'internal', 'waf', 'integrity', 'cloudflare', 'license', 'update', 'performance', 'admin', 'audit' );
	/**
	 * Diagnostic storage configuration.
	 *
	 * @var array
	 */
	public const LEVELS = array( 'error', 'info', 'debug', 'trace' );
	/**
	 * Diagnostic storage configuration.
	 *
	 * @var array
	 */
	public const EVENTS = array( 'event.redacted', 'plugin.activated', 'plugin.deactivated', 'plugin.boot', 'plugin.started', 'php.error', 'php.fatal', 'wordpress.error', 'internal.error', 'audit.started', 'audit.completed', 'audit.failed', 'settings.updated', 'settings.restored', 'logs.exported', 'logs.pruned', 'admin.action', 'performance.request', 'waf.detected', 'waf.blocked', 'integrity.changed', 'cloudflare.request', 'license.checked', 'update.checked' );

	/**
	 * Project metadata and discard arbitrary request or error text.
	 *
	 * @param array $context Untrusted structured metadata.
	 * @return array
	 */
	public static function context( array $context ): array {
		$result = array();
		foreach ( array( 'count', 'duration_ms', 'status_code', 'error_type', 'line', 'memory_bytes', 'size_bytes', 'files', 'deleted', 'dropped', 'range_hours' ) as $key ) {
			if ( isset( $context[ $key ] ) && ( is_int( $context[ $key ] ) || is_float( $context[ $key ] ) ) && is_finite( (float) $context[ $key ] ) && $context[ $key ] >= 0 ) {
				$result[ $key ] = min( $context[ $key ], PHP_INT_MAX );
			}
		}
		foreach ( array( 'enabled', 'success' ) as $key ) {
			if ( isset( $context[ $key ] ) && is_bool( $context[ $key ] ) ) {
				$result[ $key ] = $context[ $key ];
			}
		}
		if ( isset( $context['version'] ) && is_string( $context['version'] ) && preg_match( '/^\d{1,3}\.\d{1,3}\.\d{1,3}(?:-(?:dev(?:\.[1-9]\d{0,2})?|rc\.\d{1,3}))?$/D', $context['version'] ) ) {
			$result['version'] = $context['version'];
		}
		if ( isset( $context['channel'] ) && in_array( $context['channel'], array( 'dev', 'rc', 'stable' ), true ) ) {
			$result['channel'] = $context['channel'];
		}
		if ( isset( $context['commit'] ) && is_string( $context['commit'] ) && preg_match( '/^[a-f0-9]{40}$/D', $context['commit'] ) ) {
			$result['commit'] = $context['commit'];
		}
		return $result;
	}

	/**
	 * Accept only registered static developer event codes.
	 *
	 * @param string $event Untrusted event code.
	 * @return string
	 */
	public static function event( string $event ): string {
		return in_array( $event, self::EVENTS, true ) ? $event : 'event.redacted';
	}

	/**
	 * Rebuild a persisted record before export.
	 *
	 * @param array $record Untrusted persisted JSON object.
	 * @return array|null
	 */
	public static function record( array $record ): ?array {
		if ( ! isset( $record['timestamp'], $record['level'], $record['category'], $record['event'] ) || ! is_string( $record['timestamp'] ) || ! preg_match( '/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/D', $record['timestamp'] ) ) {
			return null;
		}
		if ( ! in_array( $record['level'], self::LEVELS, true ) || ! in_array( $record['category'], self::CATEGORIES, true ) || ! is_string( $record['event'] ) ) {
			return null;
		}
		return array(
			'schema'    => 1,
			'timestamp' => $record['timestamp'],
			'level'     => $record['level'],
			'category'  => $record['category'],
			'event'     => self::event( $record['event'] ),
			'context'   => self::context( is_array( $record['context'] ?? null ) ? $record['context'] : array() ),
		);
	}

	/**
	 * Project environment metadata without hosts or PHP info dumps.
	 *
	 * @param array $environment Environment and build metadata.
	 * @return array
	 */
	public static function environment( array $environment ): array {
		$result = self::context( $environment );
		foreach ( array( 'php_version', 'wordpress_version' ) as $key ) {
			if ( isset( $environment[ $key ] ) && is_string( $environment[ $key ] ) && preg_match( '/^\d{1,3}\.\d{1,3}(?:\.\d{1,3})?$/D', $environment[ $key ] ) ) {
				$result[ $key ] = $environment[ $key ];
			}
		}
		return $result;
	}
}
