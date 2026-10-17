<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Content;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Integrity\WordPressOptions;
final class WordPressContentService {
	public function create(): ContentService {
		$host = wp_parse_url( home_url(), PHP_URL_HOST );
		if ( ! is_string( $host ) || '' === $host ) {
			throw new \RuntimeException( 'Site hostname unavailable.' );
		}
		$host = strtolower( rtrim( $host, '.' ) );
		return new ContentService( new WordPressOptions(), new WordPressContentInventory( $GLOBALS['wpdb'] ), new MarkupDetector( $host ), hash( 'sha256', $host . ':' . MarkupDetector::VERSION ) );
	}
}
