<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Network;

use AmazingPlugins\Security\Integrity\OptionGateway;
final class NetworkSettingsService {
	private mixed $raw = null;
	public function __construct( private readonly OptionGateway $options ) {}
	public function status(): array {
		$this->raw = $this->options->get( 'amsec_network_policy' );
		return ( new NetworkPolicy() )->read( $this->raw ) ?? array( 'invalid' => true );}
	public function fingerprint(): string {
		$this->status();
		return ( new NetworkPolicy() )->fingerprint( $this->raw );}
	public function apply( string $expected, string $mode, array $rules, array $methods, string $operator ): string {
		$s = $this->status();
		if ( ! empty( $s['invalid'] ) ) {
			return 'invalid';
		}if ( ( new NetworkPolicy() )->fingerprint( $this->raw ) !== $expected ) {
			return 'changed';
		}if ( count( $rules ) > 50 ) {
			return 'unsupported';
		}$cidrs = array();
		foreach ( $rules as $rule ) {
			$cidr = is_string( $rule ) ? Cidr::canonical( $rule ) : null;
			if ( null === $cidr ) {
				return 'unsupported';
			}$cidrs[] = $cidr;}
		$candidate = array(
			'version'  => 1,
			'mode'     => $mode,
			'cidrs'    => $cidrs,
			'methods'  => $methods,
			'revision' => bin2hex( random_bytes( 16 ) ),
		);
	 // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Pure exact policy serialization.
		$encoded = json_encode( $candidate, JSON_THROW_ON_ERROR );
		if ( null === ( new NetworkPolicy() )->read( $encoded ) ) {
			return 'unsupported';}
		if ( 'block' === $mode ) {
			if ( ! Cidr::validAddress( $operator ) ) {
				return 'self-lockout';
			}foreach ( $cidrs as $cidr ) {
				if ( Cidr::contains( $cidr, $operator ) ) {
					return 'self-lockout';}
			}
		}
		$ok = null === $this->raw ? $this->options->add( 'amsec_network_policy', $encoded ) : $this->options->replaceIfSame( 'amsec_network_policy', $this->raw, $encoded );
		return $ok && $this->options->get( 'amsec_network_policy' ) === $encoded ? 'saved' : 'failed';
	}
	public function disable(): bool {
	 // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Explicit host recovery resets corrupt policy to off.
		$encoded = json_encode(
			array(
				'version'  => 1,
				'mode'     => 'off',
				'cidrs'    => array(),
				'methods'  => array( '*' ),
				'revision' => bin2hex( random_bytes( 16 ) ),
			),
			JSON_THROW_ON_ERROR
		);
		$this->options->set( 'amsec_network_policy', $encoded );
		$this->options->delete( 'amsec_network_observation' );
		return $this->options->get( 'amsec_network_policy' ) === $encoded;
	}
}
