<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Baseline;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Integrity\OptionGateway;

final class BaselineRepository {
	public const KEY = 'amsec_custom_baseline_state';

	public function __construct( private readonly OptionGateway $options ) {}

	public function snapshot(): array {
		$raw = $this->options->get( self::KEY );
		if ( null === $raw ) {
			return array(
				null,
				array(
					'version'   => 1,
					'baselines' => array(),
					'previews'  => array(),
				),
			);
		}
		if ( ! is_string( $raw ) || strlen( $raw ) > 524288 ) {
			throw new \RuntimeException( 'Baseline storage unavailable.' );
		}
		$state = json_decode( $raw, true );
		$this->validate( $state );
		return array( $raw, $state );
	}

	public function save( ?string $expected, array $state ): void {
		$this->validate( $state );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Shared deterministic storage works in pure-PHP tests.
		$value = json_encode( $state, JSON_THROW_ON_ERROR );
		if ( strlen( $value ) > 524288 || ! ( null === $expected ? $this->options->add( self::KEY, $value ) : $this->options->replaceIfSame( self::KEY, $expected, $value ) ) ) {
			throw new \RuntimeException( 'Baseline state changed or storage unavailable. Preview again.' );
		}
	}

	private function validate( mixed $state ): void {
		if ( ! is_array( $state ) || 1 !== ( $state['version'] ?? null ) || ! is_array( $state['baselines'] ?? null ) || ! is_array( $state['previews'] ?? null ) || count( $state['baselines'] ) > 10 || count( $state['previews'] ) > 10 ) {
			throw new \RuntimeException( 'Invalid baseline state.' );
		}
		foreach ( array( 'baselines', 'previews' ) as $kind ) {
			foreach ( $state[ $kind ] as $row ) {
				if ( ! is_array( $row ) || ! is_string( $row['key'] ?? null ) || strlen( $row['key'] ) > 256 || ! is_string( $row['stamp'] ?? null ) || ! preg_match( '/^[a-f0-9]{64}$/D', $row['stamp'] ) || ! is_array( $row['files'] ?? null ) ) {
					throw new \RuntimeException( 'Invalid baseline row.' );
				}
				new BaselineManifest( $row['files'] );
				if ( 'previews' === $kind && ( ! is_int( $row['expires'] ?? null ) || ! is_string( $row['token'] ?? null ) || ! preg_match( '/^[a-f0-9]{32}$/D', $row['token'] ) || ! is_string( $row['previous'] ?? null ) ) ) {
					throw new \RuntimeException( 'Invalid preview.' );
				}
			}
		}
	}
}
