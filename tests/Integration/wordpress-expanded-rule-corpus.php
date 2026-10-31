<?php
// Read-only corpus on the named disposable Docker databases; never executes scanned file contents.
if ( ! defined( 'WP_CLI' ) || ! WP_CLI || 'amsec-next-db' !== DB_HOST || ! in_array( DB_NAME, array( 'wordpress', 'wordpress69' ), true ) ) {
	exit( 1 ); }
use AmazingPlugins\Security\FileScan\BundledRulePack;
use AmazingPlugins\Security\FileScan\RuleMatcher;
$matcher = new RuleMatcher( new BundledRulePack() );
$roots   = array( ABSPATH . 'wp-admin', ABSPATH . 'wp-includes', WP_PLUGIN_DIR . '/akismet', WP_PLUGIN_DIR . '/amsec-security-scanner', WP_PLUGIN_DIR . '/contact-form-7', WP_PLUGIN_DIR . '/classic-editor', WP_CONTENT_DIR . '/themes' );
if ( is_dir( WP_PLUGIN_DIR . '/woocommerce' ) ) {
	$roots[] = WP_PLUGIN_DIR . '/woocommerce'; }
$paths = glob( ABSPATH . '*.php' );
foreach ( $roots as $root ) {
	if ( ! is_dir( $root ) ) {
		continue; }
	foreach ( new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS ) ) as $file ) {
		if ( ! $file->isLink() && $file->isFile() && preg_match( '/\.php$/iD', $file->getFilename() ) ) {
			$paths[] = $file->getPathname(); }
	}
}
sort( $paths );
$paths = array_unique( $paths );
if ( count( $paths ) > 20000 ) {
	throw new RuntimeException( 'Corpus inventory limit exceeded.' ); }
$digest  = hash_init( 'sha256' );
$checked = 0;
$skipped = array();
$hits    = array();
$started = microtime( true );
foreach ( $paths as $path ) {
	$relative = substr( $path, strlen( ABSPATH ) );
	if ( is_link( $path ) || filesize( $path ) > 2097152 ) {
		$skipped[ $relative ] = 'oversized_or_symlink';
		continue; }
	$bytes = file_get_contents( $path );
	if ( false === $bytes ) {
		$skipped[ $relative ] = 'unreadable';
		continue; }
	hash_update( $digest, $relative . ':' . hash( 'sha256', $bytes ) . "\n" );
	try {
		$found = $matcher->match( $bytes, $relative ); } catch ( RuntimeException $e ) {
		$skipped[ $relative ] = $e->getMessage();
		continue; }
		++$checked;
		foreach ( $found as $hit ) {
			$hits[] = array(
				'path' => $relative,
				'rule' => $hit->ruleId,
				'line' => $hit->line,
			); }
}
echo json_encode(
	array(
		'wordpress'         => get_bloginfo( 'version' ),
		'woocommerce'       => defined( 'WC_VERSION' ) ? WC_VERSION : null,
		'rule_pack'         => ( new BundledRulePack() )->version(),
		'files_inventoried' => count( $paths ),
		'files_checked'     => $checked,
		'excluded'          => $skipped,
		'review_hits'       => $hits,
		'corpus_sha256'     => hash_final( $digest ),
		'seconds'           => round( microtime( true ) - $started, 3 ),
		'peak_bytes'        => memory_get_peak_usage( true ),
	),
	JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES
) . PHP_EOL;
