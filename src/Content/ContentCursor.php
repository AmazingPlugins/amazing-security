<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Content;

defined( 'ABSPATH' ) || exit;

final class ContentCursor {
	public string $phase   = 'post';
	public int $after      = 0;
	public int $processed  = 0;
	public int $bytes      = 0;
	public float $elapsed  = 0.0;
	public int $unknown    = 0;
	public int $omitted    = 0;
	public bool $partial   = false;
	public bool $finished  = false;
	public int $finishedAt = 0;
	public string $reason  = '';
	public array $findings = array();
	public function __construct( public readonly string $scanId, public readonly int $postMax, public readonly int $commentMax, public readonly int $startedAt, public readonly string $context ) {
		if ( ! preg_match( '/^[a-zA-Z0-9-]{1,80}$/D', $scanId ) || $postMax < 0 || $commentMax < 0 || $startedAt < 1 || ! preg_match( '/^[a-f0-9]{64}$/D', $context ) ) {
			throw new \InvalidArgumentException( 'Invalid content scan.' );
		}
	}
	public function toArray(): array {
		return array(
			'version'     => 1,
			'scan_id'     => $this->scanId,
			'post_max'    => $this->postMax,
			'comment_max' => $this->commentMax,
			'started_at'  => $this->startedAt,
			'context'     => $this->context,
			'phase'       => $this->phase,
			'after'       => $this->after,
			'processed'   => $this->processed,
			'bytes'       => $this->bytes,
			'elapsed'     => $this->elapsed,
			'unknown'     => $this->unknown,
			'omitted'     => $this->omitted,
			'partial'     => $this->partial,
			'finished'    => $this->finished,
			'finished_at' => $this->finishedAt,
			'reason'      => $this->reason,
			'findings'    => $this->findings,
		);
	}
	public static function fromArray( array $data ): ?self {
		if ( 1 !== ( $data['version'] ?? null ) || ! is_string( $data['scan_id'] ?? null ) || ! is_string( $data['context'] ?? null ) || ! in_array( $data['phase'] ?? '', array( 'post', 'comment', 'done' ), true ) || ! is_array( $data['findings'] ?? null ) || count( $data['findings'] ) > 250 || ! is_bool( $data['partial'] ?? null ) || ! is_bool( $data['finished'] ?? null ) || ! in_array( $data['reason'] ?? '', array( '', 'budget', 'database', 'expired', 'context' ), true ) || ! ( is_int( $data['elapsed'] ?? null ) || is_float( $data['elapsed'] ?? null ) ) || ! is_finite( (float) $data['elapsed'] ) || $data['elapsed'] < 0 ) {
			return null;
		}
		foreach ( array( 'post_max', 'comment_max', 'started_at', 'after', 'processed', 'bytes', 'unknown', 'omitted', 'finished_at' ) as $key ) {
			if ( ! is_int( $data[ $key ] ?? null ) || $data[ $key ] < 0 ) {
					return null;
			}
		}
		if ( $data['processed'] > 1000 || $data['bytes'] > 16777216 || $data['unknown'] > $data['processed'] || $data['omitted'] > 4000 || ( 'done' !== $data['phase'] && $data['after'] > $data[ 'post' === $data['phase'] ? 'post_max' : 'comment_max' ] ) ) {
			return null;
		}
		foreach ( $data['findings'] as $finding ) {
			if ( ! is_array( $finding ) || 6 !== count( $finding ) || ! in_array( $finding['kind'] ?? '', array( 'post', 'comment' ), true ) || ! is_int( $finding['id'] ?? null ) || $finding['id'] < 1 || ! in_array( $finding['rule'] ?? '', MarkupDetector::RULES, true ) || ! is_int( $finding['line'] ?? null ) || $finding['line'] < 1 || $finding['line'] > 131073 || ! is_string( $finding['version'] ?? null ) || ! preg_match( '/^[0-9.]{1,32}$/D', $finding['version'] ) || ! is_int( $finding['tested_at'] ?? null ) || $finding['tested_at'] < 1 ) {
				return null;
			}
		}
		try {
			$cursor = new self( $data['scan_id'], $data['post_max'], $data['comment_max'], $data['started_at'], $data['context'] );
		} catch ( \Throwable ) {
			return null;
		}
		foreach ( array( 'phase', 'after', 'processed', 'bytes', 'unknown', 'omitted', 'partial', 'finished', 'reason', 'findings' ) as $key ) {
			$cursor->$key = $data[ $key ];
		}
		$cursor->elapsed    = (float) $data['elapsed'];
		$cursor->finishedAt = $data['finished_at'];
		return $cursor;
	}
}
