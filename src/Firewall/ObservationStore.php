<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Firewall;

use AmazingPlugins\Security\Integrity\OptionGateway;

final class ObservationStore {
	private const OPTION = 'amsec_rest_observations';

	public function __construct( private readonly OptionGateway $options ) {}

	public function summary(): array {
		$raw  = $this->options->get( self::OPTION );
		$data = is_string( $raw ) ? json_decode( $raw, true ) : null;
		if ( ! is_array( $data ) ) {
			return array();
		}
		$result = array();
		foreach ( ( new BundledRequestRules() )->ids() as $rule ) {
			$item = $data[ $rule ] ?? null;
			if ( is_array( $item ) && isset( $item['count'], $item['last_at'] ) && is_int( $item['count'] ) && is_int( $item['last_at'] ) ) {
				$result[ $rule ] = array(
					'count'   => $item['count'],
					'last_at' => $item['last_at'],
				);
			}
		}
		return $result;
	}

	public function record( array $rules, int $now ): bool {
		if ( array() === $rules || $now < 1 || array_diff( $rules, ( new BundledRequestRules() )->ids() ) ) {
			return false;
		}
		for ( $attempt = 0; $attempt < 3; ++$attempt ) {
			$previous = $this->options->get( self::OPTION );
			$data     = $this->summary();
			foreach ( array_unique( $rules ) as $rule ) {
				$old           = $data[ $rule ] ?? array(
					'count'   => 0,
					'last_at' => 0,
				);
				$data[ $rule ] = array(
					'count'   => min( 9999, $old['count'] + 1 ),
					'last_at' => $now,
				);
			}
			// phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Pure PHP storage tests use the shared option gateway.
			$value = json_encode( $data, JSON_THROW_ON_ERROR );
			if ( is_string( $previous ) ? $this->options->replaceIfSame( self::OPTION, $previous, $value ) : $this->options->add( self::OPTION, $value ) ) {
				return true;
			}
		}
		return false;
	}
}
