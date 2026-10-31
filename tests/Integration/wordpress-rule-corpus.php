<?php

// Run only with wp eval-file on a disposable site with AmSec Security Scanner active.
use AmazingPlugins\Security\FileScan\BundledRulePack;
use AmazingPlugins\Security\FileScan\RuleMatcher;

$matcher = new RuleMatcher( new BundledRulePack() );
$checked = 0;
$hits = array();
foreach ( array( WP_PLUGIN_DIR . '/akismet', WP_PLUGIN_DIR . '/hello.php', WP_PLUGIN_DIR . '/amsec-security-scanner', WP_CONTENT_DIR . '/themes' ) as $root ) {
	if ( is_file( $root ) ) {
		$bytes = file_get_contents( $root );
		if ( false === $bytes ) {
			throw new RuntimeException( 'Could not read a bundled plugin file.' );
		}
		++$checked;
		foreach ( $matcher->match( $bytes, $root ) as $hit ) {
			$hits[] = $hit->ruleId . ':' . str_replace( WP_CONTENT_DIR . '/', '', $root );
		}
		continue;
	}
	$files = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS ) );
	foreach ( $files as $file ) {
		if ( $file->isLink() || ! $file->isFile() || ! preg_match( '/\.php$/i', $file->getFilename() ) || $file->getSize() > 2097152 ) {
			continue;
		}
		if ( ++$checked > 2000 ) {
			throw new RuntimeException( 'Benign corpus limit exceeded.' );
		}
		$bytes = file_get_contents( $file->getPathname() );
		if ( false === $bytes ) {
			throw new RuntimeException( 'Could not read a benign corpus file.' );
		}
		foreach ( $matcher->match( $bytes, $file->getPathname() ) as $hit ) {
			$hits[] = $hit->ruleId . ':' . str_replace( WP_CONTENT_DIR . '/', '', $file->getPathname() );
		}
	}
}
if ( array() !== $hits ) {
	throw new RuntimeException( 'Bundled benign corpus produced review hits: ' . implode( ', ', $hits ) );
}
echo 'Bundled plugin and theme PHP corpus: ' . $checked . ' files, no rule hits.';
