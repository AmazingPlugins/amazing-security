<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Proxy;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Network\Cidr;
final class ProxyResolver {
	public function resolve( ?array $policy, array $server, bool $peerConfirmed ): ?string {
		$peer = $this->address( $server['REMOTE_ADDR'] ?? null );
		if ( null === $policy || null === $peer ) {
			return null; }
		if ( 'off' === $policy['mode'] ) {
			return $peer; }
		if ( ! $peerConfirmed ) {
			return null; }
		if ( ! $this->trusted( $peer, $policy['cidrs'] ) ) {
			return $peer; }
		$header = $server[ 'single' === $policy['mode'] ? 'HTTP_CF_CONNECTING_IP' : 'HTTP_X_FORWARDED_FOR' ] ?? null;
		if ( ! is_string( $header ) || '' === $header || strlen( $header ) > 2048 || 1 === preg_match( '/[\x00-\x1f\x7f]/', $header ) ) {
			return null; }
		if ( 'single' === $policy['mode'] ) {
			return $this->address( trim( $header, ' ' ) ); }
		$tokens = explode( ',', $header );
		if ( count( $tokens ) > 32 ) {
			return null; }
		$chain = array();
		foreach ( $tokens as $token ) {
			$address = $this->address( trim( $token, ' ' ) );
			if ( null === $address ) {
					return null;
			} $chain[] = $address; }
		for ( $i = count( $chain ) - 1; $i >= 0; --$i ) {
			if ( ! $this->trusted( $chain[ $i ], $policy['cidrs'] ) ) {
					return $chain[ $i ]; }
		}
		return null;
	}
	private function address( mixed $raw ): ?string {
		if ( ! is_string( $raw ) || ! Cidr::validAddress( $raw ) ) {
			return null; }
		$canonical = Cidr::canonical( $raw );
		return null === $canonical ? null : explode( '/', $canonical )[0];
	}
	private function trusted( string $address, array $cidrs ): bool {
		foreach ( $cidrs as $cidr ) {
			if ( Cidr::contains( $cidr, $address ) ) {
				return true;
			}
		} return false; }
}
