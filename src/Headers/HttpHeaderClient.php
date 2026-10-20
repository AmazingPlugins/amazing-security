<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Headers;

defined( 'ABSPATH' ) || exit;

use Closure;

/** Anonymous HEAD of the homepage through the WordPress HTTP API, with no redirects. */
final class HttpHeaderClient implements HeaderClient {
	private readonly Closure $request;
	public function __construct( ?callable $request = null ) {
		$this->request = Closure::fromCallable( $request ?? 'wp_safe_remote_head' );
	}
	public function fetch( string $raw ): array {
		$parser = new HeaderAssessment();
		$url    = HeaderTarget::url( $raw );
		if ( null === $url ) {
			return $parser->unknown();}
		try {
			$response = ( $this->request )(
				$url,
				array(
					'timeout'     => 5,
					'redirection' => 0,
					'sslverify'   => true,
					'user-agent'  => 'AmazingSecurity-header-assessment/0.1',
				)
			);
			// A WP_Error is an object, so this also covers failed requests.
			if ( ! is_array( $response ) ) {
				return $parser->unknown();}
			$headers = array();
			foreach ( array_merge( array( 'content-type' ), array_values( HeaderAssessment::NAMES ) ) as $name ) {
				$value = $response['headers'][ $name ] ?? null;
				if ( null !== $value ) {
					$headers[ $name ] = array_values( array_map( 'strval', (array) $value ) );}
			}
			return $parser->parse( (int) ( $response['response']['code'] ?? 0 ), $headers, str_starts_with( $url, 'https://' ) );
		} catch ( \Throwable ) {
			return $parser->unknown();}
	}
}
