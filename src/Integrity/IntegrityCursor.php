<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Integrity;

use AmazingPlugins\Security\Findings\CheckResult;
use DateTimeImmutable;

final class IntegrityCursor {
	/** @param CheckResult[] $findings */
	public function __construct( public readonly string $scanId, public int $targetIndex = 0, public int $fileIndex = 0, public int $processed = 0, public int $matched = 0, public int $bytes = 0, public float $elapsed = 0.0, public array $findings = array(), public readonly ?DateTimeImmutable $startedAt = null, public bool $partial = false, public string $targetSignature = '', public array $packages = array() ) {}

	public function toArray(): array {
		return array(
			'version'          => 1,
			'scan_id'          => $this->scanId,
			'target_index'     => $this->targetIndex,
			'file_index'       => $this->fileIndex,
			'processed'        => $this->processed,
			'matched'          => $this->matched,
			'bytes'            => $this->bytes,
			'elapsed'          => $this->elapsed,
			'findings'         => array_map( static fn( CheckResult $finding ): array => $finding->toArray(), $this->findings ),
			'started_at'       => ( $this->startedAt ?? new DateTimeImmutable() )->format( 'c' ),
			'partial'          => $this->partial,
			'target_signature' => $this->targetSignature,
			'packages'         => $this->packages,
		);
	}

	public static function fromArray( array $data ): ?self {
		if ( 1 !== ( $data['version'] ?? null ) || ! isset( $data['scan_id'], $data['target_index'], $data['file_index'], $data['processed'], $data['matched'], $data['bytes'], $data['elapsed'], $data['findings'], $data['started_at'] ) ) {
			return null;
		}
		if ( ! is_string( $data['scan_id'] ) || ! preg_match( '/^[a-zA-Z0-9-]{1,80}$/D', $data['scan_id'] ) || ! is_int( $data['target_index'] ) || ! is_int( $data['file_index'] ) || ! is_int( $data['processed'] ) || ! is_int( $data['matched'] ) || ! is_int( $data['bytes'] ) || ! is_numeric( $data['elapsed'] ) || ! is_array( $data['findings'] ) ) {
			return null;
		}
		if ( $data['target_index'] < 0 || $data['file_index'] < 0 || $data['processed'] < 0 || $data['processed'] > 5000 || $data['matched'] < 0 || $data['matched'] > $data['processed'] || $data['bytes'] < 0 || $data['bytes'] > 134217728 || (float) $data['elapsed'] < 0 || count( $data['findings'] ) > 250 ) {
			return null;
		}
		if ( ! is_array( $data['packages'] ?? array() ) || count( $data['packages'] ?? array() ) > 11 ) {
			return null;
		}
		foreach ( $data['packages'] ?? array() as $package => $counts ) {
			if ( ! is_string( $package ) || ! is_array( $counts ) || ! isset( $counts['total'], $counts['checked'], $counts['matched'], $counts['warn'], $counts['inconclusive'], $counts['source_url'], $counts['fetched_at'] ) ) {
				return null;
			}
			foreach ( array( 'total', 'checked', 'matched', 'warn', 'inconclusive' ) as $counter ) {
				if ( ! is_int( $counts[ $counter ] ) || $counts[ $counter ] < 0 ) {
					return null;
				}
			}
			if ( $counts['checked'] > $counts['total'] || $counts['matched'] > $counts['checked'] || $counts['warn'] + $counts['inconclusive'] + $counts['matched'] > $counts['checked'] || ! is_string( $counts['source_url'] ) || ! str_starts_with( $counts['source_url'], 'https://' ) || ! filter_var( $counts['source_url'], FILTER_VALIDATE_URL ) || ! is_string( $counts['fetched_at'] ) ) {
				return null;
			}
		}
		try {
			return new self( (string) $data['scan_id'], (int) $data['target_index'], (int) $data['file_index'], (int) $data['processed'], (int) $data['matched'], (int) $data['bytes'], (float) $data['elapsed'], array_map( array( CheckResult::class, 'fromArray' ), $data['findings'] ), new DateTimeImmutable( $data['started_at'] ), (bool) ( $data['partial'] ?? false ), (string) ( $data['target_signature'] ?? '' ), $data['packages'] ?? array() );
		} catch ( \Throwable $error ) {
			return null;
		}
	}
}
