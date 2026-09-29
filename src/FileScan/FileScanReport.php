<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\FileScan;

use DateTimeImmutable;

final class FileScanReport {
	public function __construct( public readonly string $scanId, public readonly string $state, public readonly DateTimeImmutable $finishedAt, public readonly bool $partial, public readonly int $processed, public readonly int $bytes, public readonly int $unknown, public readonly int $excluded, public readonly int $extra, public readonly int $verified, public readonly int $scanned, public readonly int $omitted, public readonly array $findings ) {}

	public static function fromCursor( FileScanCursor $cursor ): self {
		return new self( $cursor->scanId, $cursor->state(), new DateTimeImmutable(), $cursor->partial, $cursor->processed, $cursor->bytes, $cursor->unknown, $cursor->excluded, $cursor->extra, $cursor->verified, $cursor->scanned, $cursor->omitted, $cursor->findings );
	}

	public function toArray(): array {
		return array(
			'scan_id'     => $this->scanId,
			'state'       => $this->state,
			'finished_at' => $this->finishedAt->format( 'c' ),
			'partial'     => $this->partial,
			'processed'   => $this->processed,
			'bytes'       => $this->bytes,
			'unknown'     => $this->unknown,
			'excluded'    => $this->excluded,
			'extra'       => $this->extra,
			'verified'    => $this->verified,
			'scanned'     => $this->scanned,
			'omitted'     => $this->omitted,
			'findings'    => $this->findings,
		);
	}

	public static function fromArray( array $data ): ?self {
		if ( ! is_string( $data['scan_id'] ?? null ) || ! is_string( $data['state'] ?? null ) || ! in_array( $data['state'], array( 'pass', 'warn', 'inconclusive' ), true ) || ! is_string( $data['finished_at'] ?? null ) || ! is_bool( $data['partial'] ?? null ) || ! is_array( $data['findings'] ?? null ) || count( $data['findings'] ) > 250 ) {
			return null;
		}
		foreach ( array( 'processed', 'bytes', 'unknown', 'excluded', 'extra', 'verified', 'scanned', 'omitted' ) as $key ) {
			if ( ! is_int( $data[ $key ] ?? null ) || $data[ $key ] < 0 ) {
				return null;
			}
		}
		try {
			return new self( $data['scan_id'], $data['state'], new DateTimeImmutable( $data['finished_at'] ), $data['partial'], $data['processed'], $data['bytes'], $data['unknown'], $data['excluded'], $data['extra'], $data['verified'], $data['scanned'], $data['omitted'], $data['findings'] );
		} catch ( \Throwable $error ) {
			return null;
		}
	}
}
