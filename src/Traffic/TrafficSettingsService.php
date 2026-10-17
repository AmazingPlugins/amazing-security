<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Traffic;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Integrity\OptionGateway;
final class TrafficSettingsService {
	private mixed $raw = null;
	public function __construct( private readonly OptionGateway $options ) {}
	public function status(): array {
		$this->raw = $this->options->get( 'amsec_traffic_policy' );
		return ( new TrafficPolicy() )->read( $this->raw ) ?? array( 'invalid' => true ); }
	public function fingerprint(): string {
		$this->status();
		return ( new TrafficPolicy() )->fingerprint( $this->raw ); }
	public function apply( string $expected, bool $enabled ): string {
		if ( ! empty( $this->status()['invalid'] ) ) {
			return 'invalid'; }
		if ( ( new TrafficPolicy() )->fingerprint( $this->raw ) !== $expected ) {
			return 'changed'; }
		$encoded = $this->encode( $enabled );
		$ok      = null === $this->raw ? $this->options->add( 'amsec_traffic_policy', $encoded ) : $this->options->replaceIfSame( 'amsec_traffic_policy', $this->raw, $encoded );
		return $ok && $this->options->get( 'amsec_traffic_policy' ) === $encoded ? 'saved' : 'failed';
	}
	public function disable(): bool {
		$s = $this->encode( false );
		$this->options->set( 'amsec_traffic_policy', $s );
		return $this->options->get( 'amsec_traffic_policy' ) === $s; }
	private function encode( bool $enabled ): string {
	 // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Pure fixed policy serialization.
		return json_encode(
			array(
				'version'  => 1,
				'enabled'  => $enabled,
				'revision' => bin2hex( random_bytes( 16 ) ),
			),
			JSON_THROW_ON_ERROR
		);
	}
}
