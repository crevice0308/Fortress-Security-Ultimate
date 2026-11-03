<?php
/**
 * Private, bounded, hourly JSONL security log.
 *
 * @package FortressSecurityUltimate
 */

namespace Fortress\Security\Log;

// phpcs:disable WordPress.WP.AlternativeFunctions -- Native private local locking, permissions and throwing JSON are required; remote WP_Filesystem transports cannot provide these guarantees.

/** Logger diagnostic service. */
final class Logger {
	/**
	 * Diagnostic storage configuration.
	 *
	 * @var int
	 */
	public const RETENTION_SECONDS = 604800;
	/**
	 * Diagnostic storage configuration.
	 *
	 * @var int
	 */
	public const MAX_FILE_BYTES = 8388608;
	/**
	 * Diagnostic storage configuration.
	 *
	 * @var string
	 */
	private string $directory;
	/**
	 * Diagnostic storage configuration.
	 *
	 * @var bool
	 */
	private bool $debug;
	/**
	 * Diagnostic storage configuration.
	 *
	 * @var array
	 */
	private array $categories;
	/**
	 * Diagnostic storage configuration.
	 *
	 * @var int
	 */
	private int $max_bytes;
	/**
	 * Diagnostic storage configuration.
	 *
	 * @var \Closure
	 */
	private \Closure $clock;

	/**
	 * Set up dedicated, private log storage.
	 *
	 * @param string    $directory Absolute storage directory.
	 * @param array     $public_roots Verified public document roots.
	 * @param bool      $debug Whether detailed logs are enabled.
	 * @param array     $categories Allowed names or explicit category booleans.
	 * @param int       $max_bytes Total managed storage quota.
	 * @param ?callable $clock Optional test clock returning Unix seconds.
	 * @throws \RuntimeException If private storage cannot be used safely.
	 */
	public function __construct( string $directory, array $public_roots = array(), bool $debug = true, array $categories = array(), int $max_bytes = 524288000, ?callable $clock = null ) {
		$directory = rtrim( $directory, '/\\' );
		if ( '' === $directory || str_contains( $directory, "\0" ) || ! preg_match( '~^(?:/|[A-Za-z]:[\\\\/])~', $directory ) || preg_match( '~(?:^|[\\\\/])\.\.(?:[\\\\/]|$)~', $directory ) ) {
			throw new \RuntimeException( 'FSU log directory must be an absolute private path.' );
		}
		self::assert_no_symlinks( $directory );
		if ( ! is_dir( $directory ) && ! @mkdir( $directory, 0700, true ) && ! is_dir( $directory ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Checked private I/O failures must not expose paths or corrupt downloads.
			throw new \RuntimeException( 'FSU private log directory cannot be created.' );
		}
		$canonical = realpath( $directory );
		if ( false === $canonical || ! is_dir( $canonical ) ) {
			throw new \RuntimeException( 'FSU private log directory is invalid.' );
		}
		foreach ( $public_roots as $root ) {
			if ( ! is_string( $root ) || '' === $root ) {
				continue;
			}
			$public = realpath( $root );
			if ( false === $public ) {
				throw new \RuntimeException( 'FSU public root cannot be verified.' );
			}
			if ( self::inside( $canonical, $public ) ) {
				throw new \RuntimeException( 'FSU logs must be outside every public document root.' );
			}
		}
		foreach ( new \DirectoryIterator( $canonical ) as $entry ) {
			if ( $entry->isDot() ) {
				continue;
			}
			if ( ! preg_match( '/^(?:\.lock|fsu-\d{8}-\d{2}\.jsonl|export-[a-f0-9]{32}\.(?:zip|jsonl))$/D', $entry->getFilename() ) || ! self::regular_private_file( $entry->getPathname() ) ) {
				throw new \RuntimeException( 'FSU requires a dedicated directory containing only its regular diagnostic files.' );
			}
		}
		if ( ! @chmod( $canonical, 0700 ) || ! @is_writable( $canonical ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Checked private I/O failures must not expose paths or corrupt downloads.
			throw new \RuntimeException( 'FSU private log directory permissions cannot be secured.' );
		}
		$this->directory  = $canonical;
		$this->debug      = $debug;
		$this->categories = $categories;
		if ( array_is_list( $categories ) && array() !== $categories ) {
			$this->categories = array_fill_keys( Redactor::CATEGORIES, false );
			foreach ( $categories as $category ) {
				if ( is_string( $category ) && in_array( $category, Redactor::CATEGORIES, true ) ) {
					$this->categories[ $category ] = true;
				}
			}
		}
		$this->max_bytes = max( 4096, min( 524288000, $max_bytes ) );
		$this->clock     = null === $clock ? static fn(): int => time() : \Closure::fromCallable( $clock );
	}

	/**
	 * Check a canonical path against a canonical root.
	 *
	 * @param string $path Canonical path.
	 * @param string $root Canonical public root.
	 * @return bool
	 */
	private static function inside( string $path, string $root ): bool {
		$path = str_replace( '\\', '/', $path );
		$root = rtrim( str_replace( '\\', '/', $root ), '/' );
		if ( '\\' === DIRECTORY_SEPARATOR ) {
			$path = strtolower( $path );
			$root = strtolower( $root );
		}
		return $path === $root || str_starts_with( $path, $root . '/' );
	}

	/**
	 * Reject symlink components in a storage path.
	 *
	 * @param string $path Absolute path.
	 * @return void
	 * @throws \RuntimeException If private storage cannot be used safely.
	 */
	private static function assert_no_symlinks( string $path ): void {
		$current = $path;
		while ( '' !== $current && dirname( $current ) !== $current ) {
			if ( is_link( $current ) ) {
				throw new \RuntimeException( 'FSU log paths cannot contain symlinks.' );
			}
			$current = dirname( $current );
		}
	}


	/**
	 * Reject nonregular files and hardlinks.
	 *
	 * @param string $path Existing local path.
	 * @return bool
	 */
	private static function regular_private_file( string $path ): bool {
		$stat = @lstat( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Checked private I/O failures must not expose paths or corrupt downloads.
		return false !== $stat && ( $stat['mode'] & 0170000 ) === 0100000 && 1 === $stat['nlink'];
	}


	/**
	 * Read a regular file size without exposing a native error path.
	 *
	 * @param string $path Managed private path.
	 * @return int
	 * @throws \RuntimeException If the file cannot be inspected.
	 */
	private static function size( string $path ): int {
		$size = @filesize( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Failure is converted into a sanitized exception.
		if ( false === $size ) {
			throw new \RuntimeException( 'FSU cannot inspect a private storage file.' );
		}
		return $size;
	}

	/**
	 * Return the private storage directory.
	 *
	 * @return string
	 */
	public function directory(): string {
		return $this->directory;
	}

	/**
	 * Return the current Unix timestamp.
	 *
	 * @return int
	 */
	public function now(): int {
		return (int) ( $this->clock )();
	}

	/**
	 * Run an operation under the nonblocking storage lock.
	 *
	 * @param callable $callback Operation to serialize.
	 * @return mixed
	 * @throws \RuntimeException If private storage cannot be used safely.
	 */
	public function with_lock( callable $callback ): mixed {
		self::assert_no_symlinks( $this->directory );
		clearstatcache();
		$path = $this->directory . '/.lock';
		if ( is_link( $path ) || ( file_exists( $path ) && ! self::regular_private_file( $path ) ) ) {
			throw new \RuntimeException( 'FSU unsafe lock file.' );
		}
		$old_umask = umask( 0077 );
		try {
			$handle = @fopen( $path, 'c+b' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Checked private I/O failures must not expose paths or corrupt downloads.
		} finally {
			umask( $old_umask );
		}
		if ( false === $handle ) {
			throw new \RuntimeException( 'FSU cannot open log lock.' );
		}
		try {
			if ( ! @chmod( $path, 0600 ) || ! @flock( $handle, LOCK_EX | LOCK_NB ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Checked private I/O failures must not expose paths or corrupt downloads.
				throw new \RuntimeException( 'FSU log storage is busy or unavailable.' );
			}
			return $callback();
		} finally {
			@flock( $handle, LOCK_UN ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Checked private I/O failures must not expose paths or corrupt downloads.
			@fclose( $handle ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Checked private I/O failures must not expose paths or corrupt downloads.
		}
	}

	/**
	 * Append a typed, projected diagnostic event.
	 *
	 * @param string $level Error, Info, Debug or Trace.
	 * @param string $category Fixed diagnostic category.
	 * @param string $event Static developer event code.
	 * @param array  $context Typed diagnostic metadata.
	 * @return bool
	 */
	public function log( string $level, string $category, string $event, array $context = array() ): bool {
		$level = strtolower( $level );
		if ( ! in_array( $level, Redactor::LEVELS, true ) || ( ! $this->debug && in_array( $level, array( 'debug', 'trace' ), true ) ) ) {
			return false;
		}
		$category = in_array( $category, Redactor::CATEGORIES, true ) ? $category : 'internal';
		if ( isset( $this->categories[ $category ] ) && false === $this->categories[ $category ] && 'error' !== $level ) {
			return false;
		}
		try {
			$record = array(
				'schema'    => 1,
				'timestamp' => gmdate( 'Y-m-d\TH:i:s\Z', $this->now() ),
				'level'     => $level,
				'category'  => $category,
				'event'     => Redactor::event( $event ),
				'context'   => Redactor::context( $context ),
			);
			$line   = json_encode( $record, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR ) . "\n";
			return (bool) $this->with_lock(
				function () use ( $line ): bool {
					$this->prune_locked( strlen( $line ) );
					$path = $this->directory . '/fsu-' . gmdate( 'Ymd-H', $this->now() ) . '.jsonl';
					if ( is_link( $path ) || ( file_exists( $path ) && ! self::regular_private_file( $path ) ) || ( file_exists( $path ) && self::size( $path ) + strlen( $line ) > self::MAX_FILE_BYTES ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Checked private I/O failures must not expose paths or corrupt downloads.
							return false;
					}
					$old_umask = umask( 0077 );
					try {
						$handle = @fopen( $path, 'ab' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Checked private I/O failures must not expose paths or corrupt downloads.
					} finally {
						umask( $old_umask );
					}
					if ( false === $handle ) {
						return false;
					}
					try {
						if ( ! @chmod( $path, 0600 ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Checked private I/O failures must not expose paths or corrupt downloads.
							return false;
						}
						$written = strlen( $line ) === @fwrite( $handle, $line ) && @fflush( $handle ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Checked private I/O failures must not expose paths or corrupt downloads.
						clearstatcache( true, $path );
						return $written;
					} finally {
						@fclose( $handle ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Checked private I/O failures must not expose paths or corrupt downloads.
					}
				}
			);
		} catch ( \Throwable $error ) {
			return false;
		}
	}

	/**
	 * List known regular hourly files in chronological order.
	 *
	 * @return array
	 */
	public function files(): array {
		$files = array();
		foreach ( new \DirectoryIterator( $this->directory ) as $entry ) {
			if ( ! $entry->isLink() && $entry->isFile() && self::regular_private_file( $entry->getPathname() ) && preg_match( '/^fsu-\d{8}-\d{2}\.jsonl$/D', $entry->getFilename() ) ) {
				$files[] = $entry->getPathname();
			}
		}
		sort( $files, SORT_STRING );
		return $files;
	}

	/**
	 * List regular files owned by the log subsystem.
	 *
	 * @return array
	 */
	private function managed_files(): array {
		$files = $this->files();
		foreach ( new \DirectoryIterator( $this->directory ) as $entry ) {
			if ( ! $entry->isLink() && $entry->isFile() && self::regular_private_file( $entry->getPathname() ) && preg_match( '/^export-[a-f0-9]{32}\.(?:zip|jsonl)$/D', $entry->getFilename() ) ) {
				$files[] = $entry->getPathname();
			}
		}
		return $files;
	}

	/**
	 * Prune whole expired buckets and reserve space while holding the storage lock.
	 *
	 * @param int  $reserved_bytes Bytes to reserve for the next operation.
	 * @param bool $compact_partial Whether to compact the cutoff bucket during scheduled cleanup.
	 * @return void
	 * @throws \RuntimeException If private storage cannot be used safely.
	 */
	public function prune_locked( int $reserved_bytes = 0, bool $compact_partial = false ): void {
		$cutoff = $this->now() - self::RETENTION_SECONDS;
		foreach ( $this->files() as $path ) {
			$bucket = \DateTimeImmutable::createFromFormat( '!Ymd-H', substr( basename( $path ), 4, 11 ), new \DateTimeZone( 'UTC' ) );
			if ( false !== $bucket && $bucket->getTimestamp() + 3600 <= $cutoff ) {
				@unlink( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Checked private I/O failures must not expose paths or corrupt downloads.
			} elseif ( $compact_partial && false !== $bucket && $bucket->getTimestamp() < $cutoff ) {
				$this->expire_partial_file( $path, $cutoff );
			}
		}
		$files = $this->managed_files();
		foreach ( $files as $path ) {
			if ( str_starts_with( basename( $path ), 'export-' ) && @filemtime( $path ) < $this->now() - 900 ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Checked private I/O failures must not expose paths or corrupt downloads.
				@unlink( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Checked private I/O failures must not expose paths or corrupt downloads.
			}
		}
		$files = array_values( array_filter( $this->managed_files(), 'is_file' ) );
		sort( $files, SORT_STRING ); // Exports first, followed by the oldest hourly logs.
		$total = array_sum( array_map( static fn( string $path ): int => self::size( $path ), $files ) );
		foreach ( $files as $path ) {
			if ( str_starts_with( basename( $path ), 'export-' ) ) {
				continue; // Fresh exports have a 15-minute lease while being downloaded.
			}
			if ( $total + $reserved_bytes <= $this->max_bytes ) {
				break;
			}
			$size = self::size( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Checked private I/O failures must not expose paths or corrupt downloads.
			if ( @unlink( $path ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Checked private I/O failures must not expose paths or corrupt downloads.
				$total -= $size;
			}
		}
		if ( $total + $reserved_bytes > $this->max_bytes ) {
			throw new \RuntimeException( 'FSU storage quota is reserved by active downloads or unavailable files.' );
		}
	}


	/**
	 * Compact the cutoff bucket to enforce the exact retention window.
	 *
	 * @param string $path Regular hourly log path.
	 * @param int    $cutoff Earliest retained Unix timestamp.
	 * @return void
	 */
	private function expire_partial_file( string $path, int $cutoff ): void {
		if ( self::size( $path ) > self::MAX_FILE_BYTES ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Checked private I/O failures must not expose paths or corrupt downloads.
			@unlink( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Checked private I/O failures must not expose paths or corrupt downloads.
			return;
		}
		$contents = @file_get_contents( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Checked private I/O failures must not expose paths or corrupt downloads.
		if ( false === $contents ) {
			return;
		}
		$kept = '';
		foreach ( explode( "\n", $contents ) as $line ) {
			if ( '' === $line || strlen( $line ) > 8192 ) {
				continue;
			}
			$record    = json_decode( $line, true, 8 );
			$record    = is_array( $record ) ? Redactor::record( $record ) : null;
			$timestamp = null === $record ? false : strtotime( $record['timestamp'] );
			if ( false !== $timestamp && $timestamp >= $cutoff && $timestamp <= $this->now() ) {
				$kept .= json_encode( $record, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR ) . "\n";
			}
		}
		if ( '' === $kept ) {
			@unlink( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Checked private I/O failures must not expose paths or corrupt downloads.
		} elseif ( $kept !== $contents ) {
			$handle = @fopen( $path, 'c+b' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Checked private I/O failures must not expose paths or corrupt downloads.
			if ( false !== $handle ) {
				try {
					if ( strlen( $kept ) === @fwrite( $handle, $kept ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Checked private I/O failures must not expose paths or corrupt downloads.
						@ftruncate( $handle, strlen( $kept ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Checked private I/O failures must not expose paths or corrupt downloads.
						@fflush( $handle ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Checked private I/O failures must not expose paths or corrupt downloads.
					}
				} finally {
					@fclose( $handle ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Checked private I/O failures must not expose paths or corrupt downloads.
				}
			}
		}
	}

	/**
	 * Run best-effort bounded retention cleanup.
	 *
	 * @return void
	 */
	public function prune(): void {
		try {
			$this->with_lock( fn() => $this->prune_locked( 0, true ) );
		} catch ( \Throwable $error ) {
			// Storage failures never change the response of a public request.
			return;
		}
	}

	/**
	 * Return nonsecret storage diagnostics.
	 *
	 * @return array
	 */
	public function stats(): array {
		clearstatcache();
		try {
			$files = $this->files();
			return array(
				'files'           => count( $files ),
				'size_bytes'      => array_sum( array_map( static fn( string $path ): int => self::size( $path ), $this->managed_files() ) ),
				'max_bytes'       => $this->max_bytes,
				'retention_hours' => 168,
				'debug'           => $this->debug,
				'available'       => true,
			);
		} catch ( \Throwable $error ) {
			return array(
				'files'           => 0,
				'size_bytes'      => 0,
				'max_bytes'       => $this->max_bytes,
				'retention_hours' => 168,
				'debug'           => $this->debug,
				'available'       => false,
			);
		}
	}
}
