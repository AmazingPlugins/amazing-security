<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\FileScan;

use AmazingPlugins\Security\Findings\State;
use AmazingPlugins\Security\Integrity\WordPressOrgManifestProvider;

final class FileScanCursor {
	public function __construct( public readonly string $scanId, public int $targetIndex = 0, public array $stack = array(), public int $processed = 0, public int $bytes = 0, public float $elapsed = 0.0, public int $unknown = 0, public int $excluded = 0, public int $extra = 0, public int $verified = 0, public int $scanned = 0, public bool $partial = false, public bool $finished = false, public string $targetSignature = '', public array $findings = array(), public int $omitted = 0 ) {}

	public function toArray(): array {
		return array(
			'version'          => 1,
			'scan_id'          => $this->scanId,
			'target_index'     => $this->targetIndex,
			'stack'            => $this->stack,
			'processed'        => $this->processed,
			'bytes'            => $this->bytes,
			'elapsed'          => $this->elapsed,
			'unknown'          => $this->unknown,
			'excluded'         => $this->excluded,
			'extra'            => $this->extra,
			'verified'         => $this->verified,
			'scanned'          => $this->scanned,
			'partial'          => $this->partial,
			'finished'         => $this->finished,
			'target_signature' => $this->targetSignature,
			'findings'         => $this->findings,
			'omitted'          => $this->omitted,
		);
	}

	public function state(): string {
		foreach ( $this->findings as $finding ) {
			if ( State::WARN === ( $finding['state'] ?? '' ) ) {
				return State::WARN;
			}
		}
		return $this->partial || $this->unknown > 0 || ! $this->finished ? State::INCONCLUSIVE : State::PASS;
	}

	public static function fromArray( array $data ): ?self {
		if ( 1 !== ( $data['version'] ?? null ) || ! is_string( $data['scan_id'] ?? null ) || ! preg_match( '/^[a-zA-Z0-9-]{1,80}$/D', $data['scan_id'] ) || ! is_array( $data['stack'] ?? null ) || count( $data['stack'] ) > 32 || ! is_array( $data['findings'] ?? null ) || count( $data['findings'] ) > 250 ) {
			return null;
		}
		foreach ( $data['stack'] as $frame ) {
			if ( ! is_array( $frame ) || ! is_string( $frame['path'] ?? null ) || ! is_string( $frame['last'] ?? null ) || ! is_string( $frame['hash'] ?? null ) || ( '' !== $frame['path'] && ! WordPressOrgManifestProvider::safePath( $frame['path'] ) ) || ( '' !== $frame['last'] && ! WordPressOrgManifestProvider::safePath( $frame['last'] ) ) || ( '' !== $frame['hash'] && ! preg_match( '/^[a-f0-9]{64}$/D', $frame['hash'] ) ) ) {
				return null;
			}
		}
		$ints = array( 'target_index', 'processed', 'bytes', 'unknown', 'excluded', 'extra', 'verified', 'scanned', 'omitted' );
		foreach ( $ints as $key ) {
			if ( ! is_int( $data[ $key ] ?? null ) || $data[ $key ] < 0 ) {
				return null;
			}
		}
		if ( $data['processed'] > 5000 || $data['bytes'] > 134217728 || $data['target_index'] > 100 || ! is_numeric( $data['elapsed'] ?? null ) || (float) $data['elapsed'] < 0 || (float) $data['elapsed'] > 35 || ! is_bool( $data['partial'] ?? null ) || ! is_bool( $data['finished'] ?? null ) || ! is_string( $data['target_signature'] ?? null ) || ( '' !== $data['target_signature'] && ! preg_match( '/^[a-f0-9]{64}$/D', $data['target_signature'] ) ) ) {
			return null;
		}
		return new self( $data['scan_id'], $data['target_index'], $data['stack'], $data['processed'], $data['bytes'], (float) $data['elapsed'], $data['unknown'], $data['excluded'], $data['extra'], $data['verified'], $data['scanned'], $data['partial'], $data['finished'], $data['target_signature'], $data['findings'], $data['omitted'] );
	}
}
