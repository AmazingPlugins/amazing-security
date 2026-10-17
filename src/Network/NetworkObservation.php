<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Network;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Integrity\OptionGateway;
final class NetworkObservation {
	private mixed $raw = null;
	public function __construct( private readonly OptionGateway $options ) {}
	public function status(): array {
		$this->raw = $this->options->get( 'amsec_network_observation' );
		if ( null === $this->raw ) {
			return array(
				'version'     => 1,
				'revision'    => str_repeat( '0', 32 ),
				'count'       => 0,
				'captured_at' => 0,
			);}
	 // phpcs:ignore WordPress.WP.AlternativeFunctions.json_decode_json_decode -- Pure bounded redacted metric validation.
		$s = is_string( $this->raw ) && strlen( $this->raw ) <= 2048 ? json_decode( $this->raw, true ) : null;
		return is_array( $s ) && array_keys( $s ) === array( 'version', 'revision', 'count', 'captured_at' ) && 1 === $s['version'] && is_string( $s['revision'] ) && 1 === preg_match( '/^[a-f0-9]{32}$/D', $s['revision'] ) && is_int( $s['count'] ) && $s['count'] >= 0 && $s['count'] <= 1000000 && is_int( $s['captured_at'] ) && $s['captured_at'] >= 0 ? $s : array( 'invalid' => true );
	}
	public function record( string $revision, int $now ): bool {
		if ( 1 !== preg_match( '/^[a-f0-9]{32}$/D', $revision ) || $now < 1 ) {
			return false;
		}$s = $this->status();
		if ( ! empty( $s['invalid'] ) || $s['captured_at'] > $now ) {
			return false;
		}if ( $s['revision'] !== $revision ) {
			$s = array(
				'version'     => 1,
				'revision'    => $revision,
				'count'       => 0,
				'captured_at' => 0,
			);
		}if ( $s['count'] >= 1000000 ) {
			return true;
		}++$s['count'];
		$s['captured_at'] = $now;
	 // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Only revision/count/time are stored, never visitor information.
		$encoded = json_encode( $s, JSON_THROW_ON_ERROR );
		return null === $this->raw ? $this->options->add( 'amsec_network_observation', $encoded ) : $this->options->replaceIfSame( 'amsec_network_observation', $this->raw, $encoded );
	}
}
