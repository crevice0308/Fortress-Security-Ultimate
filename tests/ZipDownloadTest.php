<?php
/**
 * Failure-path privacy and archive delivery regression tests.
 *
 * @package FortressSecurityUltimate
 */

namespace Fortress\Security\Tests;

use Fortress\Security\Admin\ZipDownload;
use PHPUnit\Framework\TestCase;

/** Protect the response from private paths and incomplete archives. */
final class ZipDownloadTest extends TestCase {
	/**
	 * Local disposable directory.
	 *
	 * @var string
	 */
	private string $directory;

	/** Set up an isolated fixture directory. */
	protected function setUp(): void {
		$this->directory = sys_get_temp_dir() . '/fsu-download-test-' . bin2hex( random_bytes( 8 ) );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_mkdir -- Isolated native fixture without WordPress dependency.
		mkdir( $this->directory, 0700 );
	}

	/** Delete disposable fixtures. */
	protected function tearDown(): void {
		foreach ( glob( $this->directory . '/*' ) as $path ) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- Isolated fixture cleanup.
			unlink( $path );
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_rmdir -- Isolated fixture cleanup.
		rmdir( $this->directory );
	}

	/** The original bytes and expected length are preserved. */
	public function test_complete_binary_delivery(): void {
		$path = $this->directory . '/archive.zip';
		$zip  = new \ZipArchive();
		$zip->open( $path, \ZipArchive::CREATE );
		$zip->addFromString( 'manifest.json', '{"schema":1}' );
		$zip->close();
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Read an isolated binary fixture.
		$expected = file_get_contents( $path );
		$download = ZipDownload::open( $path );
		ob_start();
		$sent = ZipDownload::send( $download['stream'], $download['size'] );
		$body = ob_get_clean();
		ZipDownload::cleanup( $download['stream'], $path );
		self::assertTrue( $sent );
		self::assertSame( $expected, $body );
		self::assertFileDoesNotExist( $path );
	}

	/** Missing files are rejected before a success response can be sent. */
	public function test_missing_file_has_no_path_or_unsuppressed_warning(): void {
		$warnings = array();
		// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_set_error_handler -- Observe only unsuppressed warnings in this regression.
		set_error_handler(
			static function ( int $severity, string $message ) use ( &$warnings ): bool {
			// phpcs:ignore WordPress.PHP.DevelopmentFunctions.prevent_path_disclosure_error_reporting,WordPress.PHP.DiscouragedPHPFunctions.runtime_configuration_error_reporting -- Read the error mask without changing it.
				if ( error_reporting() & $severity ) {
					$warnings[] = $message;
				}
				return true;
			}
		);
		try {
			try {
				ZipDownload::open( $this->directory . '/missing.zip' );
				self::fail( 'Missing archive was accepted.' );
			} catch ( \RuntimeException $error ) {
				self::assertStringNotContainsString( $this->directory, $error->getMessage() );
			}
			ZipDownload::cleanup( null, $this->directory . '/missing.zip' );
			self::assertSame( array(), $warnings );
		} finally {
			restore_error_handler();
		}
	}

	/** A truncated descriptor is reported without adding diagnostic text to bytes. */
	public function test_short_read_is_detected(): void {
		$path = $this->directory . '/archive.zip';
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Isolated native fixture without WordPress dependency.
		file_put_contents( $path, 'archive-bytes' );
		$download = ZipDownload::open( $path );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- Isolated native fixture without WordPress dependency.
		$writer = fopen( $path, 'wb' );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Isolated native fixture without WordPress dependency.
		fclose( $writer );
		ob_start();
		$sent = ZipDownload::send( $download['stream'], $download['size'] );
		$body = ob_get_clean();
		ZipDownload::cleanup( $download['stream'], $path );
		self::assertFalse( $sent );
		self::assertSame( '', $body );
	}

	/** Symlinks cannot turn a generated-archive delivery into a different file. */
	public function test_symlink_is_rejected(): void {
		$target = $this->directory . '/target.zip';
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Isolated native fixture without WordPress dependency.
		file_put_contents( $target, 'private-data' );
		symlink( $target, $this->directory . '/link.zip' );
		$this->expectException( \RuntimeException::class );
		ZipDownload::open( $this->directory . '/link.zip' );
	}

	/** Buffered text must not be prepended to the attachment bytes. */
	public function test_existing_buffered_output_is_discarded_before_download(): void {
		$script = <<<'PHP'
ob_start();
echo 'private earlier output';
ob_start();
echo 'nested private output';
ZipDownload::prepare_response();
if (ob_get_level() !== 0) {
    exit(1);
}
$archive = ZipDownload::open($path);
$sent = ZipDownload::send($archive['stream'], $archive['size']);
ZipDownload::cleanup($archive['stream'], null);
exit($sent ? 0 : 2);
PHP;
		$result = $this->isolated_response( $script );
		self::assertSame( 0, $result['exit'], $result['error'] );
		self::assertSame( $result['expected'], $result['output'] );
		self::assertSame( '', $result['error'] );
	}

	/** A removable compression handler must not rewrite the binary body. */
	public function test_compression_buffer_is_removed_before_download(): void {
		$script = <<<'PHP'
ob_start('ob_gzhandler');
echo 'private compressed output';
ZipDownload::prepare_response();
if (ob_get_level() !== 0) {
    exit(1);
}
$archive = ZipDownload::open($path);
$sent = ZipDownload::send($archive['stream'], $archive['size']);
ZipDownload::cleanup($archive['stream'], null);
exit($sent ? 0 : 2);
PHP;
		$result = $this->isolated_response( $script );
		self::assertSame( 0, $result['exit'], $result['error'] );
		self::assertSame( $result['expected'], $result['output'] );
		self::assertSame( '', $result['error'] );
	}

	/** Incompatible buffers are rejected before archive headers or bytes. */
	public function test_nonremovable_buffer_is_rejected_in_an_isolated_process(): void {
		$script = <<<'PHP'
ob_start(null, 0, PHP_OUTPUT_HANDLER_CLEANABLE | PHP_OUTPUT_HANDLER_FLUSHABLE);
echo 'private pending output';
try {
    ZipDownload::prepare_response();
    ob_clean();
    exit(1);
} catch (RuntimeException $error) {
    ob_clean();
    if (headers_sent() || str_contains($error->getMessage(), $path)) {
        exit(2);
    }
    fwrite(STDOUT, 'rejected');
}
PHP;
		$result = $this->isolated_response( $script );
		self::assertSame( 0, $result['exit'], $result['error'] );
		self::assertSame( 'rejected', $result['output'] );
		self::assertSame( '', $result['error'] );
	}

	/** A non-cleanable buffer must never be flushed to begin an attachment. */
	public function test_noncleanable_buffer_is_rejected_in_an_isolated_process(): void {
		$script = <<<'PHP'
ob_start(null, 0, PHP_OUTPUT_HANDLER_REMOVABLE);
echo 'private pending output';
try {
    ZipDownload::prepare_response();
    ob_end_clean();
    exit(1);
} catch (RuntimeException $error) {
    ob_end_clean();
    if (headers_sent()) {
        exit(2);
    }
    echo 'rejected';
}
PHP;
		$result = $this->isolated_response( $script );
		self::assertSame( 0, $result['exit'], $result['error'] );
		self::assertSame( 'rejected', $result['output'] );
		self::assertSame( '', $result['error'] );
	}

	/** Callback failures must not expose their private error messages. */
	public function test_throwing_buffer_callback_becomes_a_generic_failure(): void {
		$script = <<<'PHP'
ob_start(static function (string $buffer): string {
    throw new RuntimeException('private callback message');
});
echo 'private pending output';
try {
    ZipDownload::prepare_response();
    exit(1);
} catch (RuntimeException $error) {
    if (str_contains($error->getMessage(), 'private')) {
        exit(2);
    }
    echo 'rejected';
}
PHP;
		$result = $this->isolated_response( $script );
		self::assertSame( 0, $result['exit'], $result['error'] );
		self::assertSame( 'rejected', $result['output'] );
		self::assertSame( '', $result['error'] );
	}

	/** Ordinary shutdown echo and buffer-flush attempts cannot append to a ZIP. */
	public function test_shutdown_output_is_discarded_after_download(): void {
		$script = <<<'PHP'
ZipDownload::prepare_response();
$archive = ZipDownload::open($path);
if (!ZipDownload::send($archive['stream'], $archive['size'])) {
    exit(1);
}
ZipDownload::cleanup($archive['stream'], null);
if (!ZipDownload::discard_following_output()) {
    exit(2);
}
register_shutdown_function(static function (): void {
    @ob_end_flush();
    echo str_repeat('private shutdown output', 2000);
});
PHP;
		$result = $this->isolated_response( $script );
		self::assertSame( 0, $result['exit'], $result['error'] );
		self::assertSame( $result['expected'], $result['output'] );
		self::assertSame( '', $result['error'] );
	}

	/**
	 * Exercise process-level buffering without destroying PHPUnit's own buffers.
	 *
	 * @param string $script Isolated response operation.
	 * @return array{exit:int,output:string,error:string,expected:string}
	 */
	private function isolated_response( string $script ): array {
		if ( ! function_exists( 'proc_open' ) ) {
			self::markTestSkipped( 'Process creation is required for isolated output-buffer tests.' );
		}
		$path = $this->directory . '/buffer-response.zip';
		$zip  = new \ZipArchive();
		$zip->open( $path, \ZipArchive::CREATE );
		$zip->addFromString( 'manifest.json', '{"schema":1}' );
		$zip->close();
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Read an isolated binary fixture.
		$expected = file_get_contents( $path );
		// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_var_export -- Encode a trusted path as a PHP literal for an isolated test, not debug output.
		$code = 'require ' . var_export( dirname( __DIR__ ) . '/src/autoload.php', true ) . ';'
			. 'use Fortress\\Security\\Admin\\ZipDownload;'
			// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_var_export -- Encode a trusted fixture path as PHP source without shell evaluation.
			. '$path = ' . var_export( $path, true ) . ';'
			. $script;
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.system_calls_proc_open -- Isolated fixed PHP command; array arguments avoid shell evaluation.
		$process = proc_open(
			array( PHP_BINARY, '-r', $code ),
			array(
				0 => array( 'pipe', 'r' ),
				1 => array( 'pipe', 'w' ),
				2 => array( 'pipe', 'w' ),
			),
			$pipes
		);
		self::assertIsResource( $process );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Close isolated child process input.
		fclose( $pipes[0] );
		$output = stream_get_contents( $pipes[1] );
		$error  = stream_get_contents( $pipes[2] );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Release isolated child output descriptor.
		fclose( $pipes[1] );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Release isolated child error descriptor.
		fclose( $pipes[2] );
		$exit = proc_close( $process );
		self::assertIsString( $output );
		self::assertIsString( $error );
		self::assertIsString( $expected );
		return array(
			'exit'     => $exit,
			'output'   => $output,
			'error'    => $error,
			'expected' => $expected,
		);
	}
}
