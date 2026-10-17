<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Content;

defined( 'ABSPATH' ) || exit;

use Closure;
final class ContentRunner {
	private readonly Closure $clock;
	public function __construct( private readonly ContentInventory $inventory, private readonly MarkupDetector $detector, ?callable $clock = null ) {
		$this->clock = Closure::fromCallable( $clock ?? static fn(): float => microtime( true ) );
	}
	public function step( ContentCursor $cursor, int $now ): void {
		if ( $cursor->finished ) {
			return;
		}
		$start = ( $this->clock )();
		$seen  = 0;
		try {
			while ( ! $cursor->finished && $seen < 50 ) {
				$duration = max( 0.0, ( $this->clock )() - $start );
				if ( $cursor->processed >= 1000 || $cursor->bytes >= 16777216 || $cursor->elapsed + $duration >= 30.0 ) {
					$this->stop( $cursor, 'budget', $now );
					break;
				}
				if ( $duration >= 5.0 ) {
					break;
				}
				$max  = 'post' === $cursor->phase ? $cursor->postMax : $cursor->commentMax;
				$rows = $this->inventory->candidates( $cursor->phase, $cursor->after, $max, 50 - $seen );
				if ( count( $rows ) > 50 - $seen ) {
					throw new \RuntimeException( 'Unbounded content metadata.' );
				}
				if ( array() === $rows ) {
					if ( 'post' === $cursor->phase ) {
						$cursor->phase = 'comment';
						$cursor->after = 0;
						continue;
					}
					$cursor->phase      = 'done';
					$cursor->finished   = true;
					$cursor->finishedAt = $now;
					break;
				}
				foreach ( $rows as $row ) {
					if ( $cursor->processed >= 1000 || $cursor->bytes >= 16777216 || $cursor->elapsed + max( 0.0, ( $this->clock )() - $start ) >= 30.0 ) {
						$this->stop( $cursor, 'budget', $now );
						break 2;
					}
					if ( max( 0.0, ( $this->clock )() - $start ) >= 5.0 ) {
						break 2;
					}
					if ( ! is_array( $row ) || ! is_int( $row['id'] ?? null ) || $row['id'] <= $cursor->after || $row['id'] > $max || ! is_int( $row['bytes'] ?? null ) || $row['bytes'] < 0 ) {
						throw new \RuntimeException( 'Invalid content metadata.' );
					}
					if ( $row['bytes'] <= 131072 && $row['bytes'] > 16777216 - $cursor->bytes ) {
						$this->stop( $cursor, 'budget', $now );
						break 2;
					}
					++$seen;
					++$cursor->processed;
					$cursor->after = $row['id'];
					if ( $row['bytes'] > 131072 || ! is_string( $row['hash'] ?? null ) || ! preg_match( '/^[a-f0-9]{64}$/D', $row['hash'] ) ) {
						++$cursor->unknown;
						$cursor->partial = true;
						continue;
					}
					$body = $this->inventory->read( $cursor->phase, $row['id'], $row['hash'] );
					if ( null !== $body ) {
						if ( strlen( $body ) > 131072 || strlen( $body ) > 16777216 - $cursor->bytes ) {
							$this->stop( $cursor, 'budget', $now );
							break 2; }
						$cursor->bytes += strlen( $body );
					}
					if ( null === $body || strlen( $body ) !== $row['bytes'] || hash( 'sha256', $body ) !== $row['hash'] ) {
						++$cursor->unknown;
						$cursor->partial = true;
						continue;
					}
					try {
						$hits = $this->detector->match( $body );
					} catch ( \RuntimeException ) {
								++$cursor->unknown;
								$cursor->partial = true;
								continue;
					}
					foreach ( $hits as $hit ) {
						if ( count( $cursor->findings ) >= 250 ) {
							++$cursor->omitted;
							$cursor->partial = true;
							continue;
						}
						$cursor->findings[] = array(
							'kind'      => $cursor->phase,
							'id'        => $row['id'],
							'rule'      => $hit['rule'],
							'line'      => $hit['line'],
							'version'   => MarkupDetector::VERSION,
							'tested_at' => $now,
						);
					}
					if ( $cursor->processed >= 1000 || $cursor->elapsed + max( 0.0, ( $this->clock )() - $start ) >= 30.0 ) {
						$this->stop( $cursor, 'budget', $now );
						break 2;
					}
				}
			}
		} catch ( \Throwable ) {
			$this->stop( $cursor, 'database', $now );
		} finally {
			$cursor->elapsed += max( 0.0, ( $this->clock )() - $start );
		}
	}
	private function stop( ContentCursor $cursor, string $reason, int $now ): void {
		$cursor->partial    = true;
		$cursor->finished   = true;
		$cursor->finishedAt = $now;
		$cursor->reason     = $reason;
	}
}
