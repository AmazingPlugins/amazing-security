<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Content;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Integrity\OptionGateway;
use AmazingPlugins\Security\Integrity\WorkerLock;
use RuntimeException;
final class ContentService {
	private mixed $raw = null;
	private readonly ContentRunner $runner;
	public function __construct( private readonly OptionGateway $options, private readonly ContentInventory $inventory, MarkupDetector $detector, private readonly string $context, ?callable $clock = null ) {
		$this->runner = new ContentRunner( $inventory, $detector, $clock );
	}
	public function status(): array {
		$this->raw = $this->options->get( 'amsec_content_state' );
		if ( null === $this->raw ) {
			return array(
				'version'  => 1,
				'active'   => null,
				'previous' => null,
				'complete' => null,
			);
		}
	 // phpcs:ignore WordPress.WP.AlternativeFunctions.json_decode_json_decode -- Pure option-gateway state tests.
		$state = is_string( $this->raw ) && strlen( $this->raw ) <= 262144 ? json_decode( $this->raw, true ) : null;
		if ( ! is_array( $state ) || 1 !== ( $state['version'] ?? null ) ) {
			return array( 'invalid' => true );
		}
		foreach ( array( 'active', 'previous', 'complete' ) as $key ) {
			if ( ! array_key_exists( $key, $state ) || ( null !== $state[ $key ] && ( ! is_array( $state[ $key ] ) || null === ContentCursor::fromArray( $state[ $key ] ) ) ) ) {
				return array( 'invalid' => true );
			}
		}
		return $state;
	}
	public function start( int $now ): string {
		$lock = new WorkerLock( $this->options, 'amsec_content_lock' );
		if ( ! $lock->acquire( 'content-start' ) ) {
			return 'busy';
		}
		try {
			$state = $this->status();
			if ( ! empty( $state['invalid'] ) ) {
				return 'invalid';
			}
			$active = null === $state['active'] ? null : ContentCursor::fromArray( $state['active'] );
			if ( null !== $active && ! $active->finished && $now <= $active->startedAt + 86400 ) {
				return 'busy';
			}
			if ( null !== $active && ! $active->finished ) {
				$active->partial    = true;
				$active->finished   = true;
				$active->finishedAt = $now;
				$active->reason     = 'expired';
				$state['previous']  = $active->toArray();
			}
			$bounds = $this->inventory->bounds();
			if ( ! is_int( $bounds['post'] ?? null ) || ! is_int( $bounds['comment'] ?? null ) ) {
				throw new RuntimeException( 'Content inventory unavailable.' );
			}
			$cursor          = new ContentCursor( bin2hex( random_bytes( 16 ) ), $bounds['post'], $bounds['comment'], $now, $this->context );
			$state['active'] = $cursor->toArray();
			return $this->save( $state ) ? 'started' : 'failed';
		} finally {
			$lock->release();
		}
	}
	public function step( int $now, ?string $expectedId = null ): string {
		$lock = new WorkerLock( $this->options, 'amsec_content_lock' );
		if ( ! $lock->acquire( 'content-step' ) ) {
			return 'busy';
		}
		try {
			$state = $this->status();
			if ( ! empty( $state['invalid'] ) ) {
				return 'invalid';
			}
			if ( null !== $expectedId && ( $state['active']['scan_id'] ?? '' ) !== $expectedId ) {
				return 'changed';
			}
			$cursor = null === $state['active'] ? null : ContentCursor::fromArray( $state['active'] );
			if ( null === $cursor ) {
				return 'none';
			}
			if ( $cursor->finished ) {
				return $cursor->partial ? 'partial' : 'finished';
			}
			if ( $now > $cursor->startedAt + 86400 || ! hash_equals( $cursor->context, $this->context ) ) {
				$cursor->partial    = true;
				$cursor->finished   = true;
				$cursor->finishedAt = $now;
				$cursor->reason     = $now > $cursor->startedAt + 86400 ? 'expired' : 'context';
			} else {
					$this->runner->step( $cursor, $now );
			}
			$state['active'] = $cursor->toArray();
			if ( $cursor->finished ) {
				$state['previous'] = $cursor->toArray();
				if ( ! $cursor->partial ) {
					$state['complete'] = $cursor->toArray();
				}
			}
			if ( ! $this->save( $state ) ) {
					return 'failed';
			}
			return $cursor->finished ? ( $cursor->partial ? 'partial' : 'finished' ) : 'progress';
		} finally {
			$lock->release();
		}
	}
	private function save( array $state ): bool {
	 // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Pure option-gateway state tests.
		$encoded = json_encode( $state, JSON_THROW_ON_ERROR );
		if ( strlen( $encoded ) > 262144 ) {
			return false;
		}
		$saved = null === $this->raw ? $this->options->add( 'amsec_content_state', $encoded ) : ( is_string( $this->raw ) && $this->options->replaceIfSame( 'amsec_content_state', $this->raw, $encoded ) );
		if ( $saved ) {
			$this->raw = $encoded;
		}
		return $saved;
	}
}
