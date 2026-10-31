<?php

// Run with WP-CLI eval-file after activating the preview on a disposable WordPress site.
use AmazingPlugins\Security\Integrity\HttpClient;
use AmazingPlugins\Security\Integrity\HttpResult;
use AmazingPlugins\Security\Integrity\TargetDiscovery;
use AmazingPlugins\Security\Integrity\ThemeArchiveParser;
use AmazingPlugins\Security\Integrity\WordPressOrgManifestProvider;
use AmazingPlugins\Security\Integrity\WordPressOrgThemeManifestProvider;

$theme = wp_get_theme();
if ( ! $theme->exists() ) {
	throw new RuntimeException( 'No active theme for integration fixture.' );
}
$requested = array();
$client    = new class( $requested ) implements HttpClient {
	public array $requested = array();
	public function __construct( array $requested ) {
		$this->requested = $requested; }
	public function get( string $url, int $maxBytes ): HttpResult {
		$this->requested[] = $url;
		return new HttpResult( 404, '' );
	}
};
$discovery = ( new TargetDiscovery(
	new WordPressOrgManifestProvider( $client ),
	new WordPressOrgThemeManifestProvider(
		new ThemeArchiveParser(),
		static function ( string $url ) use ( $client ): ?string {
			$client->requested[] = $url;
			return null; }
	)
) )->discover(
	'6.6',
	'en_US',
	ABSPATH,
	array(),
	array(
		array(
			'slug'       => $theme->get_stylesheet(),
			'version'    => (string) $theme->get( 'Version' ),
			'root'       => $theme->get_stylesheet_directory(),
			'update_uri' => (string) $theme->get( 'UpdateURI' ),
			'child'      => false,
		),
		array(
			'slug'       => 'custom',
			'version'    => '1.0',
			'root'       => WP_CONTENT_DIR . '/themes/custom',
			'update_uri' => 'https://vendor.example/',
			'child'      => false,
		),
		array(
			'slug'       => 'child',
			'version'    => '1.0',
			'root'       => WP_CONTENT_DIR . '/themes/child',
			'update_uri' => '',
			'child'      => true,
		),
	)
);
if ( ! $discovery->partial || count( $discovery->findings ) !== 4 || ! in_array( 'non_wordpress_org_origin', array_column( array_map( static fn( $finding ) => $finding->evidence, $discovery->findings ), 'reason' ), true ) ) {
	throw new RuntimeException( 'Theme unknown coverage was incorrectly treated as verified.' );
}
if ( ! in_array( 'https://downloads.wordpress.org/theme/' . $theme->get_stylesheet() . '.' . $theme->get( 'Version' ) . '.zip', $client->requested, true ) ) {
	throw new RuntimeException( 'Exact theme release archive was not requested.' );
}
	echo 'Theme integrity: fixed archive request, custom and child unknown coverage passed.' . PHP_EOL;
