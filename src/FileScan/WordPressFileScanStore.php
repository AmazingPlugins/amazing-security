<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\FileScan;

use AmazingPlugins\Security\Integrity\OptionGateway;
use RuntimeException;

final class WordPressFileScanStore implements FileScanStore {
	private const ACTIVE    = 'amazing_security_file_scan_active';
	private const COMPLETED = 'amazing_security_file_scan_completed';
	private const HISTORY   = 'amazing_security_file_scan_history';

	public function __construct( private readonly OptionGateway $options ) {}

	public function begin( string $scanId, FileScanCursor $cursor ): bool {
		if ( ! preg_match( '/^[a-zA-Z0-9-]{1,80}$/D', $scanId ) || $scanId !== $cursor->scanId ) {
			return false;
		}
		$previous = $this->options->get( self::ACTIVE );
		$active   = $this->decode( $previous );
		if ( null !== $active && (int) $active['expires'] >= time() && ( ! (bool) ( $active['finished'] ?? false ) || (bool) ( $active['completing'] ?? false ) ) ) {
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

	public function saveProgress( string $scanId, FileScanStep $step ): void {
		$previous = $this->options->get( self::ACTIVE );
		$active   = $this->decode( $previous );
		if ( ! is_string( $previous ) || null === $active || $active['scan_id'] !== $scanId || $step->cursor->scanId !== $scanId || (int) $active['expires'] < time() || (bool) ( $active['completing'] ?? false ) ) {
			throw new RuntimeException( 'File scan lock changed.' );
		}
		$active['cursor']   = $step->cursor->toArray();
		$active['finished'] = $step->finished;
		$active['expires']  = time() + 1800;
		$value              = $this->encode( $active );
		if ( $previous !== $value && ! $this->options->replaceIfSame( self::ACTIVE, $previous, $value ) ) {
			throw new RuntimeException( 'Could not save file scan progress.' );
		}
	}

	public function complete( string $scanId, FileScanReport $report ): void {
		$previous = $this->options->get( self::ACTIVE );
		$active   = $this->decode( $previous );
		if ( ! is_string( $previous ) || null === $active || $active['scan_id'] !== $scanId || ! $active['finished'] || $report->scanId !== $scanId || $report->partial || (int) $active['expires'] < time() ) {
			throw new RuntimeException( 'Cannot complete file scan.' );
		}
		$active['completing'] = true;
		$active['expires']    = time() + 60;
		$claimed              = $this->encode( $active );
		if ( ! $this->options->replaceIfSame( self::ACTIVE, $previous, $claimed ) ) {
			throw new RuntimeException( 'File scan lock changed before completion.' );
		}
		$previousReport = $this->options->get( self::COMPLETED );
		$value          = $this->encode( $report->toArray() );
		$saved          = null === $previousReport ? $this->options->add( self::COMPLETED, $value ) : $this->options->set( self::COMPLETED, $value );
		if ( ! $saved ) {
			$this->options->replaceIfSame( self::ACTIVE, $claimed, $previous );
			throw new RuntimeException( 'Could not save completed file scan.' );
		}
		if ( 'warn' === $report->state ) {
			$history    = array_map( static fn( FileScanReport $item ): array => $item->toArray(), $this->historicalWarnings() );
			$history[]  = $report->toArray();
			$cutoff     = time() - 90 * 86400;
			$history    = array_values( array_filter( $history, static fn( array $item ): bool => strtotime( $item['finished_at'] ) >= $cutoff ) );
			$history    = array_slice( $history, -20 );
			$oldHistory = $this->options->get( self::HISTORY );
			$encoded    = $this->encode( $history );
			if ( null === $oldHistory ) {
				$this->options->add( self::HISTORY, $encoded );
			} else {
				$this->options->set( self::HISTORY, $encoded );
			}
		}
		$this->options->deleteIfSame( self::ACTIVE, $claimed );
	}

	public function latestProgress(): ?FileScanStep {
		$active = $this->decode( $this->options->get( self::ACTIVE ) );
		$cursor = null === $active ? null : FileScanCursor::fromArray( $active['cursor'] );
		if ( null === $cursor ) {
			return null;
		}
		if ( (int) $active['expires'] < time() ) {
			$cursor->partial  = true;
			$cursor->finished = true;
		}
		return new FileScanStep( $cursor, $cursor->finished );
	}

	public function latestCompleted(): ?FileScanReport {
		$value = $this->options->get( self::COMPLETED );
		$data  = is_string( $value ) ? json_decode( $value, true ) : null;
		return is_array( $data ) ? FileScanReport::fromArray( $data ) : null;
	}

	public function historicalWarnings(): array {
		$value = $this->options->get( self::HISTORY );
		$data  = is_string( $value ) ? json_decode( $value, true ) : null;
		if ( ! is_array( $data ) ) {
			return array();
		}
		$reports = array();
		foreach ( array_slice( $data, -20 ) as $item ) {
			$report = is_array( $item ) ? FileScanReport::fromArray( $item ) : null;
			if ( null !== $report && $report->finishedAt->getTimestamp() >= time() - 90 * 86400 ) {
				$reports[] = $report;
			}
		}
		return $reports;
	}

	private function decode( mixed $value ): ?array {
		$data = is_string( $value ) ? json_decode( $value, true ) : null;
		return is_array( $data ) && isset( $data['scan_id'], $data['expires'], $data['cursor'] ) && is_array( $data['cursor'] ) ? $data : null;
	}

	private function encode( array $data ): string {
		// phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Pure storage tests also run without WordPress.
		return json_encode( $data, JSON_THROW_ON_ERROR );
	}
}
