<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Schedule;

use AmazingPlugins\Security\Integrity\OptionGateway;

final class SuiteCycle {
	private const OPTION = 'amsec_suite_cycle';

	public function __construct( private readonly OptionGateway $options ) {}

	public function status( int $now ): array {
		$raw  = $this->options->get( self::OPTION );
		$data = is_string( $raw ) ? json_decode( $raw, true ) : null;
		if ( ! is_array( $data ) || ! isset( $data['state'], $data['stage'], $data['started_at'] ) ) {
			return array(
				'state'      => 'never',
				'stage'      => '',
				'started_at' => null,
				'attempts'   => 0,
			);
		}
		if ( 'running' === $data['state'] && $now > (int) $data['started_at'] + 86400 ) {
			$data['state'] = 'partial';
		}
		return $data;
	}

	public function start( int $now ): bool {
		$raw = $this->options->get( self::OPTION );
		if ( 'running' === $this->status( $now )['state'] ) {
			return false;
		}
		$next = $this->encode(
			array(
				'state'       => 'running',
				'stage'       => 'integrity',
				'started_at'  => $now,
				'updated_at'  => $now,
				'attempts'    => 0,
				'lease_until' => 0,
			)
		);
		return is_string( $raw ) ? $this->options->replaceIfSame( self::OPTION, $raw, $next ) : $this->options->add( self::OPTION, $next );
	}

	public function allows( string $stage, int $now ): bool {
		$status = $this->status( $now );
		return 'running' === $status['state'] && $stage === $status['stage'];
	}

	public function claim( string $stage, int $now ): bool {
		if ( ! $this->allows( $stage, $now ) ) {
			return false;
		}
		return $this->update(
			$now,
			static function ( array $state ) use ( $stage, $now ): ?array {
				if ( 'running' !== $state['state'] || $stage !== $state['stage'] || (int) ( $state['lease_until'] ?? 0 ) > $now ) {
					return null;
				}
				$state['lease_until'] = $now + 600;
				$state['updated_at']  = $now;
				return $state;
			}
		);
	}

	public function continueStage( string $stage, int $now ): bool {
		if ( ! $this->allows( $stage, $now ) ) {
			return false;
		}
		return $this->update(
			$now,
			static function ( array $state ) use ( $stage, $now ): ?array {
				if ( 'running' !== $state['state'] || $stage !== $state['stage'] ) {
					return null;
				}
				$state['attempts']    = 0;
				$state['lease_until'] = 0;
				$state['updated_at']  = $now;
				return $state;
			}
		);
	}

	public function advance( string $from, string $to, int $now ): bool {
		if ( ! $this->allows( $from, $now ) ) {
			return false;
		}
		return $this->update(
			$now,
			static function ( array $state ) use ( $from, $to, $now ): ?array {
				if ( 'running' !== $state['state'] || $from !== $state['stage'] ) {
					return null;
				}
				$state['stage']       = $to;
				$state['attempts']    = 0;
				$state['lease_until'] = 0;
				$state['updated_at']  = $now;
				return $state;
			}
		);
	}

	public function retry( string $stage, int $now ): bool {
		if ( ! $this->allows( $stage, $now ) ) {
			return false;
		}
		$continue = false;
		$updated  = $this->update(
			$now,
			static function ( array $state ) use ( $stage, $now, &$continue ): ?array {
				if ( 'running' !== $state['state'] || $stage !== $state['stage'] ) {
					return null;
				}
				$state['attempts']    = (int) $state['attempts'] + 1;
				$continue             = $state['attempts'] < 3;
				$state['state']       = $continue ? 'running' : 'partial';
				$state['lease_until'] = 0;
				$state['updated_at']  = $now;
				return $state;
			}
		);
		return $updated && $continue;
	}

	public function complete( int $now ): bool {
		if ( ! $this->allows( 'files', $now ) ) {
			return false;
		}
		return $this->update(
			$now,
			static function ( array $state ) use ( $now ): ?array {
				if ( 'running' !== $state['state'] || 'files' !== $state['stage'] ) {
					return null;
				}
				$state['state']      = 'partial' === ( $state['coverage'] ?? '' ) ? 'partial' : 'complete';
				$state['updated_at'] = $now;
				return $state;
			}
		);
	}

	public function markCoverageGap( int $now ): bool {
		if ( ! $this->allows( 'files', $now ) ) {
			return false;
		}
		return $this->update(
			$now,
			static function ( array $state ) use ( $now ): ?array {
				if ( 'running' !== $state['state'] || 'files' !== $state['stage'] ) {
					return null;
				}
				$state['coverage']   = 'partial';
				$state['updated_at'] = $now;
				return $state;
			}
		);
	}

	public function fail( string $stage, int $now ): bool {
		if ( ! $this->allows( $stage, $now ) ) {
			return false;
		}
		return $this->update(
			$now,
			static function ( array $state ) use ( $stage, $now ): ?array {
				if ( 'running' !== $state['state'] || $stage !== $state['stage'] ) {
					return null;
				}
				$state['state']      = 'partial';
				$state['updated_at'] = $now;
				return $state;
			}
		);
	}

	private function update( int $now, callable $change ): bool {
		$raw   = $this->options->get( self::OPTION );
		$state = is_string( $raw ) ? json_decode( $raw, true ) : null;
		if ( ! is_string( $raw ) || ! is_array( $state ) || $now > (int) ( $state['started_at'] ?? 0 ) + 86400 ) {
			return false;
		}
		$next = $change( $state );
		return is_array( $next ) && $this->options->replaceIfSame( self::OPTION, $raw, $this->encode( $next ) );
	}

	private function encode( array $state ): string {
		// phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Pure PHP state is shared with the option gateway tests.
		return json_encode( $state, JSON_THROW_ON_ERROR );
	}
}
