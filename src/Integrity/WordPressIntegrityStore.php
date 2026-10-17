<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Integrity;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Scan\ScanRun;
use RuntimeException;

final class WordPressIntegrityStore implements IntegrityStore {
	private const ACTIVE    = 'amazing_security_integrity_active';
	private const COMPLETED = 'amazing_security_integrity_completed';

	public function __construct( private readonly OptionGateway $options ) {}

	public function begin( string $scanId, IntegrityCursor $cursor ): bool {
		if ( ! preg_match( '/^[a-zA-Z0-9-]{1,80}$/D', $scanId ) || $scanId !== $cursor->scanId ) {
			return false;
		}
		$previous = $this->options->get( self::ACTIVE );
		$active   = $this->decodeActive( $previous );
		if ( null !== $active && $active['expires'] >= time() && ( (bool) ( $active['completing'] ?? false ) || ! (bool) ( $active['finished'] ?? false ) ) ) {
			return false;
		}
		if ( is_string( $previous ) && ! $this->options->deleteIfSame( self::ACTIVE, $previous ) ) {
			return false;
		}
		return $this->options->add(
			self::ACTIVE,
			$this->encode(
				array(
					'scan_id'  => $scanId,
					'expires'  => time() + 1800,
					'cursor'   => $cursor->toArray(),
					'finished' => false,
				)
			)
		);
	}

	public function saveProgress( string $scanId, IntegrityStep $step ): void {
		$previous = $this->options->get( self::ACTIVE );
		$active   = $this->decodeActive( $previous );
		if ( null === $active || ! is_string( $previous ) || $scanId !== $active['scan_id'] || $scanId !== $step->cursor->scanId || $active['expires'] < time() || (bool) ( $active['completing'] ?? false ) ) {
			throw new RuntimeException( 'Integrity scan lock changed.' );
		}
		$active['cursor']   = $step->cursor->toArray();
		$active['finished'] = $step->finished;
		$active['expires']  = time() + 1800;
		$value              = $this->encode( $active );
		if ( $previous === $value ) {
			return;
		}
		if ( ! $this->options->replaceIfSame( self::ACTIVE, $previous, $value ) ) {
			throw new RuntimeException( 'Could not save integrity progress.' );
		}
	}

	public function complete( string $scanId, ScanRun $run ): void {
		$previousActive = $this->options->get( self::ACTIVE );
		$active         = $this->decodeActive( $previousActive );
		if ( null === $active || ! is_string( $previousActive ) || $scanId !== $active['scan_id'] || ! $active['finished'] || $run->partial || $active['expires'] < time() || (bool) ( $active['completing'] ?? false ) ) {
			throw new RuntimeException( 'Cannot replace completed integrity report.' );
		}
		$active['completing'] = true;
		$active['expires']    = time() + 60;
		$claimed              = $this->encode( $active );
		if ( ! $this->options->replaceIfSame( self::ACTIVE, $previousActive, $claimed ) ) {
			throw new RuntimeException( 'Integrity scan lock changed before completion.' );
		}
		$value    = $this->encode( $run->toArray() );
		$previous = $this->options->get( self::COMPLETED );
		$saved    = $previous === $value || ( null === $previous ? $this->options->add( self::COMPLETED, $value ) : $this->options->set( self::COMPLETED, $value ) );
		if ( ! $saved ) {
			$this->options->replaceIfSame( self::ACTIVE, $claimed, $previousActive );
			throw new RuntimeException( 'Could not save completed integrity report.' );
		}
		$this->options->deleteIfSame( self::ACTIVE, $claimed );
	}

	public function latestProgress(): ?IntegrityStep {
		$active = $this->active();
		if ( null === $active ) {
			return null;
		}
		$cursor = IntegrityCursor::fromArray( $active['cursor'] ?? array() );
		if ( null === $cursor ) {
			return null;
		}
		if ( $active['expires'] < time() ) {
			$cursor->partial = true;
			return new IntegrityStep( $cursor, true );
		}
		return new IntegrityStep( $cursor, (bool) $active['finished'] );
	}

	public function latestCompleted(): ?ScanRun {
		$value = $this->options->get( self::COMPLETED );
		if ( ! is_string( $value ) ) {
			return null;
		}
		$data = json_decode( $value, true );
		try {
			return is_array( $data ) ? ScanRun::fromArray( $data ) : null;
		} catch ( \Throwable $error ) {
			return null;
		}
	}

	private function active(): ?array {
		return $this->decodeActive( $this->options->get( self::ACTIVE ) );
	}

	private function decodeActive( mixed $value ): ?array {
		$data = is_string( $value ) ? json_decode( $value, true ) : null;
		return is_array( $data ) && isset( $data['scan_id'], $data['expires'], $data['cursor'] ) ? $data : null;
	}

	private function encode( array $data ): string {
		// phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Pure storage tests also run without WordPress loaded.
		$value = json_encode( $data, JSON_THROW_ON_ERROR );
		return $value;
	}
}
