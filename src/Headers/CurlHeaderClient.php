<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Headers;

defined( 'ABSPATH' ) || exit;

use Closure;

/** Fixed anonymous HEAD with public IPv4 pinning. No stream/proxy fallback. */
final class CurlHeaderClient implements HeaderClient {
	private readonly Closure $resolve;
	private readonly Closure $transport;
	public function __construct( ?callable $resolve = null, ?callable $transport = null ) {
		$this->resolve   = Closure::fromCallable(
			$resolve ?? static function ( string $host ): array {
		// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Resolver failure is unknown and emits no hostname diagnostics.
				$records = @dns_get_record( $host, DNS_A );
				return is_array( $records ) ? array_column( $records, 'ip' ) : array();
			}
		);
		$this->transport = Closure::fromCallable(
			$transport ?? static function ( string $url, array $options ): array {
		// phpcs:ignore WordPress.WP.AlternativeFunctions.curl_curl_init -- Required address pinning is unavailable through the same-home safe HTTP API contract.
				$curl = curl_init( $url );
				if ( false === $curl ) {
					return array( 'failed' => true );}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.curl_curl_setopt_array -- Fixed bounded anonymous HEAD, DNS pinning and no proxy/redirect fallback.
				if ( ! curl_setopt_array( $curl, $options ) ) {
					return array( 'failed' => true );}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.curl_curl_exec -- Fixed bounded anonymous HEAD, DNS pinning and no proxy/redirect fallback.
				$ok = curl_exec( $curl );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.curl_curl_getinfo -- Verify pinned connection address before accepting observations.
				$info = curl_getinfo( $curl );
				return array(
					'failed' => false === $ok,
					'code'   => $info['http_code'] ?? 0,
					'ip'     => $info['primary_ip'] ?? '',
				);
			}
		);
	}
	public function fetch( string $raw ): array {
		$parser = new HeaderAssessment();
		$url    = HeaderTarget::url( $raw );
		if ( null === $url || ! function_exists( 'curl_init' ) ) {
			return $parser->unknown();}
		try {
		 // phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url -- Already validated fixed URL.
			$p    = parse_url( $url );
			$host = $p['host'];
			$tls  = 'https' === $p['scheme'];
			$port = $tls ? 443 : 80;
			$ips  = false !== filter_var( $host, FILTER_VALIDATE_IP ) ? array( $host ) : ( $this->resolve )( $host );
			if ( ! is_array( $ips ) || ! array_is_list( $ips ) || count( $ips ) < 1 || count( $ips ) > 8 ) {
				return $parser->unknown();}
			foreach ( $ips as $ip ) {
				if ( ! is_string( $ip ) || ! HeaderTarget::publicIp( $ip ) ) {
							return $parser->unknown();}
			}
			$ip       = $ips[0];
			$headers  = array();
			$bytes    = 0;
			$lines    = 0;
			$invalid  = false;
			$callback = static function ( $handle, string $line ) use ( &$headers, &$bytes, &$lines, &$invalid ): int {
				$bytes += strlen( $line );
				++$lines;
				if ( $bytes > 16384 || $lines > 64 ) {
							$invalid = true;
						return 0;}
				if ( str_starts_with( $line, 'HTTP/' ) ) {
					$headers = array();
					return strlen( $line );}
				if ( trim( $line ) === '' ) {
					return strlen( $line );}
				$colon = strpos( $line, ':' );
				if ( false === $colon ) {
					$invalid = true;
							return 0;}
				$name = strtolower( substr( $line, 0, $colon ) );
				if ( in_array( $name, array_merge( array( 'content-type' ), array_values( HeaderAssessment::NAMES ) ), true ) ) {
					$headers[ $name ][] = trim( substr( $line, $colon + 1 ), " \t\r\n" );}
				return strlen( $line );
			};
			$options  = array(
				CURLOPT_NOBODY         => true,
				CURLOPT_RETURNTRANSFER => true,
				CURLOPT_FOLLOWLOCATION => false,
				CURLOPT_MAXREDIRS      => 0,
				CURLOPT_CONNECTTIMEOUT => 2,
				CURLOPT_TIMEOUT        => 5,
				CURLOPT_SSL_VERIFYPEER => true,
				CURLOPT_SSL_VERIFYHOST => 2,
				CURLOPT_PROXY          => '',
				CURLOPT_PROTOCOLS      => CURLPROTO_HTTP | CURLPROTO_HTTPS,
				CURLOPT_IPRESOLVE      => CURL_IPRESOLVE_V4,
				CURLOPT_RESOLVE        => array( $host . ':' . $port . ':' . $ip ),
				CURLOPT_USERAGENT      => 'AmazingSecurity-header-assessment/0.1',
				CURLOPT_HEADERFUNCTION => $callback,
			);
			$response = ( $this->transport )( $url, $options );
			if ( $invalid || ! is_array( $response ) || false !== ( $response['failed'] ?? true ) || ( $response['ip'] ?? null ) !== $ip ) {
				return $parser->unknown();}
			return $parser->parse( (int) ( $response['code'] ?? 0 ), $headers, $tls );
		} catch ( \Throwable ) {
			return $parser->unknown();}
	}
}
