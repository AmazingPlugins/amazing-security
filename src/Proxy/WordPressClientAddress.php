<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Proxy;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Integrity\OptionGateway;
use AmazingPlugins\Security\Login\AddressKey;
final class WordPressClientAddress {
	public static function peerConfirmed(): bool {
		return defined( 'AMSEC_DIRECT_PEER_CONFIRMED' ) && true === AMSEC_DIRECT_PEER_CONFIRMED; }
	private function policy( ?OptionGateway $options = null ): ?array {
		if ( defined( 'AMSEC_DISABLE_PROXY_HEADERS' ) && AMSEC_DISABLE_PROXY_HEADERS ) {
			return ( new ProxyPolicy() )->read( null ); }
		try {
			return ( new ProxyPolicy() )->read( null === $options ? get_option( 'amsec_proxy_policy', null ) : $options->get( 'amsec_proxy_policy' ) );
		} catch ( \Throwable ) {
			return null; }
	}
	public function address( array $server, ?OptionGateway $options = null ): ?string {
		return ( new ProxyResolver() )->resolve( $this->policy( $options ), $server, self::peerConfirmed() ); }
	public function key( string $salt ): AddressKey {
		$policy    = $this->policy();
		$confirmed = self::peerConfirmed();
		if ( null !== $policy && 'off' === $policy['mode'] ) {
			return new AddressKey( ProxyNamespace::salt( $salt, $policy ) ); }
		return new AddressKey( ProxyNamespace::salt( $salt, $policy ), static fn( array $server ): ?string=>( new ProxyResolver() )->resolve( $policy, $server, $confirmed ) );
	}
	public function salt( string $salt ): string {
		return ProxyNamespace::salt( $salt, $this->policy() ); }
	public function server( array $server ): array {
		$server['REMOTE_ADDR'] = $this->address( $server ) ?? '';
		return $server; }
}
