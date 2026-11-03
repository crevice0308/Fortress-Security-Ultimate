<?php
/**
 * Re-inspected and bounded private support bundles.
 *
 * @package FortressSecurityUltimate
 */

namespace Fortress\Security\Log;

// phpcs:disable WordPress.WP.AlternativeFunctions -- Native private local locking, permissions and throwing JSON are required; remote WP_Filesystem transports cannot provide these guarantees.

/** Exporter diagnostic service. */
final class Exporter {
	/**
	 * Diagnostic storage configuration.
	 *
	 * @var int
	 */
	public const MAX_CONTENT_BYTES = 16777216;
	/**
	 * Diagnostic storage configuration.
	 *
	 * @var Logger
	 */
	private Logger $logger;

	/**
	 * Use an existing private logger.
	 *
	 * @param Logger $logger Private log storage service.
	 */
	public function __construct( Logger $logger ) {
		$this->logger = $logger;
	}

	/**
	 * Build a private bundle after the caller checks capability and nonce.
	 *
	 * @param int   $hours Allowed window: 1, 24 or 168 hours.
	 * @param array $environment Nonsecret typed build metadata.
	 * @return string
	 * @throws \RuntimeException If private storage cannot be used safely.
	 * @throws \InvalidArgumentException If the range is unsupported.
	 */
	public function build( int $hours, array $environment ): string {
		if ( ! in_array( $hours, array( 1, 24, 168 ), true ) ) {
			throw new \InvalidArgumentException( 'FSU export range must be 1, 24 or 168 hours.' );
		}
		if ( ! class_exists( '\ZipArchive' ) ) {
			throw new \RuntimeException( 'FSU log export requires the PHP ZIP extension.' );
		}
		return $this->logger->with_lock(
			function () use ( $hours, $environment ): string {
				$storage = $this->logger->stats();
				$maximum = $storage['max_bytes'];
				if ( ! $storage['available'] || $maximum < 524288 ) {
					throw new \RuntimeException( 'FSU export requires at least 512 KiB of available configured log capacity.' );
				}
				$reservation   = min( 2 * self::MAX_CONTENT_BYTES + 65536, intdiv( $maximum, 4 ) );
				$content_limit = intdiv( $reservation - 65536, 2 );
				if ( $storage['size_bytes'] + $reservation > $maximum ) {
					throw new \RuntimeException( 'FSU cannot export without deleting retained logs or exceeding its quota. Clear previous downloads or increase private storage capacity.' );
				}
				$this->logger->prune_locked( $reservation );
				$now       = $this->logger->now();
				$cutoff    = $now - $hours * 3600;
				$path      = $this->logger->directory() . '/export-' . bin2hex( random_bytes( 16 ) ) . '.zip';
				$old_umask = umask( 0077 );
				try {
					$handle = @fopen( $path, 'x+b' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Checked private I/O failures must not expose paths or corrupt downloads.
				} finally {
					umask( $old_umask );
				}
				if ( false === $handle ) {
					throw new \RuntimeException( 'FSU cannot create a private export.' );
				}
				@fclose( $handle ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Checked private I/O failures must not expose paths or corrupt downloads.
				$zip    = new \ZipArchive();
				$opened = false;
				try {
					if ( ! @chmod( $path, 0600 ) || true !== @$zip->open( $path, \ZipArchive::OVERWRITE ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Checked private I/O failures must not expose paths or corrupt downloads.
						throw new \RuntimeException( 'FSU cannot open the private export ZIP.' );
					}
					$opened    = true;
					$entries   = array();
					$total     = 0;
					$count     = 0;
					$skipped   = 0;
					$truncated = false;
					foreach ( $this->logger->files() as $file ) {
						$bucket = \DateTimeImmutable::createFromFormat( '!Ymd-H', substr( basename( $file ), 4, 11 ), new \DateTimeZone( 'UTC' ) );
						if ( false === $bucket || $bucket->getTimestamp() > $now || $bucket->getTimestamp() + 3600 <= $cutoff ) {
							continue;
						}
						$input = @fopen( $file, 'rb' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Checked private I/O failures must not expose paths or corrupt downloads.
						if ( false === $input ) {
							++$skipped;
							continue;
						}
						$content = '';
						try {
							for ( $line = @fgets( $input, 8193 ); false !== $line; $line = @fgets( $input, 8193 ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Checked private I/O failures must not expose paths or corrupt downloads.
								if ( ! str_ends_with( $line, "\n" ) ) {
									$rest = @fgets( $input, 8193 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Read errors are treated as missing records.
									while ( false !== $rest && ! str_ends_with( $rest, "\n" ) ) {
										$rest = @fgets( $input, 8193 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Discard oversized physical records with bounded memory.
									}
									++$skipped;
									continue;
								}
								$record    = json_decode( $line, true, 8 );
								$record    = is_array( $record ) ? Redactor::record( $record ) : null;
								$timestamp = null === $record ? false : strtotime( $record['timestamp'] );
								if ( false === $timestamp || $timestamp < $cutoff || $timestamp > $now ) {
									++$skipped;
									continue;
								}
								$clean = json_encode( $record, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR ) . "\n";
								if ( $total + strlen( $clean ) > $content_limit ) {
									$truncated = true;
									break;
								}
								$content .= $clean;
								$total   += strlen( $clean );
								++$count;
							}
						} finally {
							@fclose( $input ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Checked private I/O failures must not expose paths or corrupt downloads.
						}
						if ( '' !== $content ) {
							$name = 'logs/' . basename( $file );
							if ( ! @$zip->addFromString( $name, $content ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Checked private I/O failures must not expose paths or corrupt downloads.
								throw new \RuntimeException( 'FSU cannot add sanitized logs to the ZIP.' );
							}
							$entries[] = array(
								'path'       => $name,
								'size_bytes' => strlen( $content ),
								'sha256'     => hash( 'sha256', $content ),
							);
						}
						if ( $truncated ) {
							break;
						}
					}
					$environment = Redactor::environment( $environment );
					$manifest    = array(
						'schema'              => 'fsu-log-export/v1',
						'generated_at'        => gmdate( 'Y-m-d\TH:i:s\Z', $now ),
						'from'                => gmdate( 'Y-m-d\TH:i:s\Z', $cutoff ),
						'to'                  => gmdate( 'Y-m-d\TH:i:s\Z', $now ),
						'range_hours'         => $hours,
						'records'             => $count,
						'skipped_records'     => $skipped,
						'truncated'           => $truncated,
						'content_limit_bytes' => $content_limit,
						'entries'             => $entries,
						'build'               => array_intersect_key( $environment, array_flip( array( 'version', 'channel', 'commit' ) ) ),
					);
					$readme      = "Fortress Security Ultimate: private diagnostic bundle\n\nTimestamps are UTC. Logs are structured JSON Lines (one JSON object per line).\nmanifest.json records the exact time range, checksums and any truncation.\nThe content cap is 16 MiB or less for smaller storage quotas; truncated=true means the bundle is incomplete.\nOnly typed, approved diagnostic metadata is exported. Raw error messages, paths, request bodies, cookies, IPs, account IDs and credentials are excluded.\nThis development bundle does not prove attack protection, a clean system or production readiness.\n";
					foreach ( array(
						'manifest.json'    => json_encode( $manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR ),
						'environment.json' => json_encode( $environment, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR ),
						'README.txt'       => $readme,
					) as $name => $content ) {
						if ( ! @$zip->addFromString( $name, $content ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Checked private I/O failures must not expose paths or corrupt downloads.
							throw new \RuntimeException( 'FSU cannot finish export metadata.' );
						}
					}
					$closed = @$zip->close(); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Checked private I/O failures must not expose paths or corrupt downloads.
					$opened = false;
					if ( ! $closed || @filesize( $path ) > 2 * $content_limit + 65536 || ! @touch( $path, $now ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Checked private I/O failures must not expose paths or corrupt downloads.
						throw new \RuntimeException( 'FSU export failed or exceeded its storage reservation.' );
					}
					return $path;
				} catch ( \Throwable $error ) {
					if ( $opened ) {
								@$zip->close(); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Checked private I/O failures must not expose paths or corrupt downloads.
					}
					if ( is_file( $path ) && ! is_link( $path ) ) {
						@unlink( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Checked private I/O failures must not expose paths or corrupt downloads.
					}
					throw $error;
				}
			}
		);
	}
}
