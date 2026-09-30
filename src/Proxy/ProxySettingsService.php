<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Proxy;

use AmazingPlugins\Security\Integrity\OptionGateway;
use AmazingPlugins\Security\Network\{Cidr, NetworkPolicy};
final class ProxySettingsService {
	private mixed $raw = null;
	public function __construct( private readonly OptionGateway $options ) {}
	public function status(): array {
		$this->raw = $this->options->get( 'amsec_proxy_policy' );
		return ( new ProxyPolicy() )->read( $this->raw ) ?? array( 'invalid' => true ); }
	public function fingerprint(): string {
		$this->status();
		return ( new ProxyPolicy() )->fingerprint( $this->raw ); }
	public function apply( string $expected, string $mode, array $rules, array $server, bool $peerConfirmed ): string {
		if ( ! empty( $this->status()['invalid'] ) ) {
			return 'invalid'; }
		if ( ( new ProxyPolicy() )->fingerprint( $this->raw ) !== $expected ) {
			return 'changed'; }
		if ( count( $rules ) > 50 ) {
			return 'unsupported'; }
		$cidrs = array();
		foreach ( $rules as $rule ) {
			$cidr = is_string( $rule ) ? Cidr::canonical( $rule ) : null;
			if ( null === $cidr ) {
				return 'unsupported';
			}$cidrs[] = $cidr; }
		$candidate = array(
			'version'  => 1,
			'mode'     => $mode,
			'cidrs'    => $cidrs,
			'revision' => bin2hex( random_bytes( 16 ) ),
		);
	 // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Pure exact local policy serialization.
		$encoded = json_encode( $candidate, JSON_THROW_ON_ERROR );
		if ( null === ( new ProxyPolicy() )->read( $encoded ) ) {
			return 'unsupported'; }
		if ( 'off' !== $mode && ! $peerConfirmed ) {
			return 'host-unverified'; }
		$operator = ( new ProxyResolver() )->resolve( $candidate, $server, $peerConfirmed );
		if ( 'off' !== $mode && null === $operator ) {
			return 'unknown-operator'; }
		$network = ( new NetworkPolicy() )->read( $this->options->get( 'amsec_network_policy' ) );
		if ( null === $network ) {
			return 'network-invalid'; }
		if ( 'block' === $network['mode'] ) {
			if ( null === $operator ) {
				return 'unknown-operator'; }
			foreach ( $network['cidrs'] as $cidr ) {
				if ( Cidr::contains( $cidr, $operator ) ) {
						return 'self-lockout'; }
			}
		}
		$ok = null === $this->raw ? $this->options->add( 'amsec_proxy_policy', $encoded ) : $this->options->replaceIfSame( 'amsec_proxy_policy', $this->raw, $encoded );
		return $ok && $this->options->get( 'amsec_proxy_policy' ) === $encoded ? 'saved' : 'failed';
	}
	public function disable(): bool {
	 // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Explicit host recovery returns to host-provided address semantics.
		$raw = json_encode(
			array(
				'version'  => 1,
				'mode'     => 'off',
				'cidrs'    => array(),
				'revision' => bin2hex( random_bytes( 16 ) ),
			),
			JSON_THROW_ON_ERROR
		);
		$this->options->set( 'amsec_proxy_policy', $raw );
		return $this->options->get( 'amsec_proxy_policy' ) === $raw;
	}
}
