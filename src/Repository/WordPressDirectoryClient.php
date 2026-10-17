<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Repository;

defined( 'ABSPATH' ) || exit;

final class WordPressDirectoryClient implements DirectoryClient {
	public function fetch( string $slug, int $now ): array {
		$parser = new DirectoryRecord();
		if ( strlen( $slug ) > 64 || ! preg_match( '/^[a-z0-9]+(?:-[a-z0-9]+)*$/D', $slug ) ) {
			return $parser->unknown();}
		$fields = array();
		foreach ( array( 'sections', 'reviews', 'screenshots', 'banners', 'icons', 'contributors', 'tags', 'ratings', 'versions', 'compatibility' ) as $field ) {
			$fields[ $field ] = 0;
		}
		$response = wp_remote_get(
			'https://api.wordpress.org/plugins/info/1.0/' . rawurlencode( $slug ) . '.json?' . http_build_query( array( 'fields' => $fields ), '', '&', PHP_QUERY_RFC3986 ),
			array(
				'timeout'             => 4,
				'redirection'         => 0,
				'sslverify'           => true,
				'reject_unsafe_urls'  => true,
				'limit_response_size' => 65537,
				'user-agent'          => 'AmazingSecurity-directory-advisory/0.1',
				'cookies'             => array(),
			)
		);
		return is_wp_error( $response ) ? $parser->unknown() : $parser->parse( (int) wp_remote_retrieve_response_code( $response ), wp_remote_retrieve_body( $response ), $slug, $now );
	}
}
