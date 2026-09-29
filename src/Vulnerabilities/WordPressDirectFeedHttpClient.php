<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Vulnerabilities;

use AmazingPlugins\Security\Integrity\HttpClient;
use AmazingPlugins\Security\Integrity\HttpResult;

final class WordPressDirectFeedHttpClient implements HttpClient {
	public function get( string $url, int $maxBytes ): HttpResult {
		$response = wp_safe_remote_get(
			$url,
			array(
				'timeout'             => 8,
				'redirection'         => 0,
				'sslverify'           => true,
				'limit_response_size' => $maxBytes + 1,
				'user-agent'          => 'AmazingSecurity/0.1.0',
				'headers'             => array( 'Accept' => 'application/json' ),
			)
		);
		if ( is_wp_error( $response ) ) {
			return new HttpResult( 0, '' );
		}
		return new HttpResult( wp_remote_retrieve_response_code( $response ), wp_remote_retrieve_body( $response ) );
	}
}
