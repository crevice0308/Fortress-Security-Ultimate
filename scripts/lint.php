<?php
/**
 * Lint project PHP using the same interpreter running this script.
 *
 * @package FortressSecurityUltimate
 */

$root   = dirname( __DIR__ );
$paths  = array( $root . '/fortress-security-ultimate.php' );
$failed = false;
foreach ( array( 'src', 'tests', 'scripts' ) as $folder ) {
	$iterator = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $root . '/' . $folder, FilesystemIterator::SKIP_DOTS ) );
	foreach ( $iterator as $item ) {
		if ( $item->isFile() && ! $item->isLink() && 'php' === $item->getExtension() ) {
			$paths[] = $item->getPathname();
		}
	}
}
sort( $paths );
foreach ( $paths as $source_path ) {
	$command = escapeshellarg( PHP_BINARY ) . ' -l ' . escapeshellarg( $source_path );
	// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.system_calls_passthru -- Development-only local lint tool; arguments are escaped.
	passthru( $command, $code );
	$failed = $failed || 0 !== $code;
}
exit( $failed ? 1 : 0 );
