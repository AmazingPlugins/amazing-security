<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Headers;

defined( 'ABSPATH' ) || exit;

use Closure;

/** Anonymous HEAD of the homepage through the WordPress HTTP API, with no redirects. */
final class HttpHeaderClient implements HeaderClient {
	private readonly Closure $request;
	private readonly Closure $resolve;
	public function __construct( ?callable $request = null, ?callable $resolve = null ) {
		$this->request = Closure::fromCallable( $request ?? 'wp_safe_remote_head' );
		$this->resolve = Closure::fromCallable( $resolve ?? static fn( string $host ): array => (array) gethostbynamel( $host ) );
	}
	public function fetch( string $raw ): array {
		$parser = new HeaderAssessment();
		$url    = HeaderTarget::url( $raw );
		if ( null === $url ) {
			return $parser->unknown();}
		try {
			// wp_safe_remote_head() trusts the home host, so refuse homes that resolve to private addresses here.
			// phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url -- Already validated fixed URL.
			$host = (string) parse_url( $url, PHP_URL_HOST );
			$ips  = false !== filter_var( $host, FILTER_VALIDATE_IP ) ? array( $host ) : ( $this->resolve )( $host );
			if ( ! is_array( $ips ) || array() === $ips || array() !== array_filter( $ips, static fn( $ip ): bool => ! is_string( $ip ) || ! HeaderTarget::publicIp( $ip ) ) ) {
				return $parser->unknown();}
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
