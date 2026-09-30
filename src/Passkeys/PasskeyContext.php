<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Passkeys;

final class PasskeyContext {
	private function __construct( private readonly string $rp, private readonly string $siteOrigin ) {}
	public static function fromSiteUrl( string $url ): ?self {
		if ( strlen( $url ) > 2048 || 1 === preg_match( '/[\x00-\x20\x7f\\\\]/', $url ) ) {
			return null; }
	 // phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url -- Pure configured URL validator, independent of WordPress runtime.
		$p = parse_url( $url );
		if ( ! is_array( $p ) || ( $p['scheme'] ?? '' ) !== 'https' || isset( $p['user'] ) || isset( $p['pass'] ) || isset( $p['query'] ) || isset( $p['fragment'] ) || ! is_string( $p['host'] ?? null ) ) {
			return null; }
		$host = strtolower( $p['host'] );
		$port = $p['port'] ?? 443;
		if ( strlen( $host ) > 253 || '' === $host || false !== filter_var( $host, FILTER_VALIDATE_IP ) || ( 'localhost' !== $host && ! str_contains( $host, '.' ) ) || 1 !== preg_match( '/[a-z]/', $host ) || ! is_int( $port ) || $port < 1 || $port > 65535 ) {
			return null; }
		foreach ( explode( '.', $host ) as $label ) {
			if ( 1 !== preg_match( '/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/D', $label ) ) {
					return null; }
		}
		return new self( $host, 'https://' . $host . ( 443 === $port ? '' : ':' . $port ) );
	}
	public function rpId(): string {
		return $this->rp; }
	public function origin(): string {
		return $this->siteOrigin; }
	public function fingerprint(): string {
		return hash( 'sha256', $this->siteOrigin ); }
	public function acceptOrigin( mixed $origin ): bool {
		return is_string( $origin ) && $origin === $this->siteOrigin; }
}
