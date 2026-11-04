<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Proxy;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Integrity\OptionGateway;
use AmazingPlugins\Security\Login\AddressKey;
final class WordPressClientAddress {
	public static function peerConfirmed(): bool {
		return defined( 'IRONLATCH_DIRECT_PEER_CONFIRMED' ) && true === IRONLATCH_DIRECT_PEER_CONFIRMED; }
	private function policy( ?OptionGateway $options = null ): ?array {
		if ( defined( 'IRONLATCH_DISABLE_PROXY_HEADERS' ) && IRONLATCH_DISABLE_PROXY_HEADERS ) {
			return ( new ProxyPolicy() )->read( null ); }
		try {
			return ( new ProxyPolicy() )->read( null === $options ? get_option( 'ironlatch_proxy_policy', null ) : $options->get( 'ironlatch_proxy_policy' ) );
		} catch ( \Throwable ) {
			return null; }
	}
	public function address( array $server, ?OptionGateway $options = null ): ?string {
		return ( new ProxyResolver() )->resolve( $this->policy( $options ), $server, self::peerConfirmed() ); }
	public function key( string $salt, bool $prefix64 = false ): AddressKey {
		$policy    = $this->policy();
		$confirmed = self::peerConfirmed();
		if ( null !== $policy && 'off' === $policy['mode'] ) {
			return new AddressKey( ProxyNamespace::salt( $salt, $policy ), null, $prefix64 ); }
		return new AddressKey( ProxyNamespace::salt( $salt, $policy ), static fn( array $server ): ?string=>( new ProxyResolver() )->resolve( $policy, $server, $confirmed ), $prefix64 );
	}
	public function salt( string $salt ): string {
		return ProxyNamespace::salt( $salt, $this->policy() ); }
	/**
	 * The only request headers address detection needs, each read and cleaned on its own.
	 *
	 * @return array<string, string>
	 */
	public static function request(): array {
		$out = array();
		foreach ( array( 'REMOTE_ADDR', 'HTTP_X_FORWARDED_FOR', 'HTTP_CF_CONNECTING_IP' ) as $key ) {
			if ( ! isset( $_SERVER[ $key ] ) || ! is_string( $_SERVER[ $key ] ) ) {
				continue;
			}
			$raw   = trim( wp_unslash( $_SERVER[ $key ] ) ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Sanitized on the next line; the unsanitized value is compared to detect forged headers.
			$clean = sanitize_text_field( $raw );
			// A header that sanitizing changes was forged or damaged. Keep it unusable instead of cleaning it into a valid address.
			$out[ $key ] = $clean === $raw ? $clean : '';
		}
		return $out;
	}
	public function server( array $server ): array {
		$server['REMOTE_ADDR'] = $this->address( $server ) ?? '';
		return $server; }
}
