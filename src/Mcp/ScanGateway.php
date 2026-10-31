<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Mcp;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Findings\FindingsRepository;
use AmazingPlugins\Security\Integrity\OptionGateway;
use AmazingPlugins\Security\Scan\LocalHardeningScanService;
use AmazingPlugins\Security\Scan\ScanRun;
use Closure;
use Throwable;

final class ScanGateway {
	private const LOCK = 'amsec_security_scanner_mcp_scan_lock';
	private readonly Closure $execute;
	private readonly Closure $read;
	private readonly Closure $clock;

	public function __construct( private readonly OptionGateway $options, ?callable $execute = null, ?callable $read = null, ?callable $clock = null ) {
		$this->execute = Closure::fromCallable( $execute ?? static fn(): ScanRun => ( new LocalHardeningScanService() )->run() );
		$this->read    = Closure::fromCallable( $read ?? static fn(): ?ScanRun => ( new FindingsRepository() )->latest() );
		$this->clock   = Closure::fromCallable( $clock ?? static fn(): int => time() );
	}

	public function start( int $userId, string $type ): array {
		if ( 'hardening' !== $type || $userId < 1 ) {
			return array(
				'schema_version' => 1,
				'state'          => 'invalid',
			);
		}
		$now      = ( $this->clock )();
		$lastKey  = 'amsec_security_scanner_mcp_scan_last_' . $userId;
		$lastTime = $this->options->get( $lastKey );
		if ( is_string( $lastTime ) && ctype_digit( $lastTime ) && (int) $lastTime + 60 > $now ) {
			return array(
				'schema_version' => 1,
				'state'          => 'cooldown',
			);
		}
		$lock = bin2hex( random_bytes( 12 ) ) . ':' . ( $now + 45 );
		if ( ! $this->options->add( self::LOCK, $lock ) ) {
			$previous = $this->options->get( self::LOCK );
			$parts    = is_string( $previous ) ? explode( ':', $previous, 2 ) : array();
			if ( count( $parts ) !== 2 || ! ctype_digit( $parts[1] ) || (int) $parts[1] >= $now || ! $this->options->replaceIfSame( self::LOCK, $previous, $lock ) ) {
				return array(
					'schema_version' => 1,
					'state'          => 'busy',
				);
			}
		}
		try {
			$run     = ( $this->execute )();
			$old     = $this->options->get( $lastKey );
			$written = null === $old ? $this->options->add( $lastKey, (string) $now ) : $this->options->set( $lastKey, (string) $now );
			if ( ! $written ) {
				return array(
					'schema_version' => 1,
					'state'          => 'error',
				);
			}
			return array(
				'schema_version' => 1,
				'state'          => 'complete',
				'scan_id'        => $this->id( $run ),
				'partial'        => $run->partial,
				'finished_at'    => $run->finishedAt->format( 'c' ),
			);
		} catch ( Throwable ) {
			return array(
				'schema_version' => 1,
				'state'          => 'error',
			);
		} finally {
			$this->options->deleteIfSame( self::LOCK, $lock );
		}
	}

	public function get( string $id ): array {
		$run = $this->latest();
		if ( null === $run || ! preg_match( '/^[a-f0-9]{32}$/D', $id ) || ! hash_equals( $this->id( $run ), $id ) ) {
			return array(
				'schema_version' => 1,
				'state'          => 'expired',
			);
		}
		return array(
			'schema_version' => 1,
			'state'          => 'complete',
			'scan_id'        => $id,
			'partial'        => $run->partial,
			'started_at'     => $run->startedAt->format( 'c' ),
			'finished_at'    => $run->finishedAt->format( 'c' ),
			'result_count'   => count( $run->results ),
		);
	}

	public function latest(): ?ScanRun {
		return ( $this->read )();
	}

	private function id( ScanRun $run ): string {
		// phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- The same canonical PHP representation is used in pure unit tests and WordPress.
		return substr( hash( 'sha256', json_encode( $run->toArray(), JSON_THROW_ON_ERROR ) ), 0, 32 );
	}
}
