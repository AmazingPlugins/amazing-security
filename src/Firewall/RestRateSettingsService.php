<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Firewall;

use AmazingPlugins\Security\Integrity\OptionGateway;
final class RestRateSettingsService {
	private mixed $raw = null;
	public function __construct( private readonly OptionGateway $options ) {}
	public function status(): array {
		$this->raw = $this->options->get( 'amsec_rest_rate_policy' );
		return ( new RestRatePolicy() )->read( $this->raw ) ?? array( 'invalid' => true );}
	public function fingerprint(): string {
		$this->status();
		return ( new RestRatePolicy() )->fingerprint( $this->raw );}
	public function apply( string $expected, string $mode, array $exemptions ): string {
		$s = $this->status();
		if ( ! empty( $s['invalid'] ) ) {
			return 'invalid';
		}if ( ( new RestRatePolicy() )->fingerprint( $this->raw ) !== $expected ) {
			return 'changed';}
		$candidate = array(
			'version'    => 1,
			'mode'       => $mode,
			'exemptions' => $exemptions,
			'revision'   => bin2hex( random_bytes( 16 ) ),
		);
	 // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Pure exact policy serialization.
		$encoded = json_encode( $candidate, JSON_THROW_ON_ERROR );
		if ( null === ( new RestRatePolicy() )->read( $encoded ) ) {
			return 'unsupported';}
		$ok = null === $this->raw ? $this->options->add( 'amsec_rest_rate_policy', $encoded ) : $this->options->replaceIfSame( 'amsec_rest_rate_policy', $this->raw, $encoded );
		return $ok && $this->options->get( 'amsec_rest_rate_policy' ) === $encoded ? 'saved' : 'failed';
	}
	public function disable(): bool {
	 // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Explicit host recovery sets a fresh off policy, including corrupt state.
		$encoded = json_encode(
			array(
				'version'    => 1,
				'mode'       => 'off',
				'exemptions' => array(),
				'revision'   => bin2hex( random_bytes( 16 ) ),
			),
			JSON_THROW_ON_ERROR
		);
		$this->options->set( 'amsec_rest_rate_policy', $encoded );
		return $this->options->get( 'amsec_rest_rate_policy' ) === $encoded;
	}
}
