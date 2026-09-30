<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Digest;

use AmazingPlugins\Security\Integrity\OptionGateway;
use AmazingPlugins\Security\Integrity\WorkerLock;
use Closure;

final class DigestDelivery {
	private const STATE = 'amsec_digest_state';
	private readonly Closure $send;
	private mixed $raw = null;
	public function __construct( private readonly OptionGateway $options, callable $send, private readonly string $email, private readonly string $dashboardUrl ) {
		$this->send = Closure::fromCallable( $send );
	}

	public function status(): array {
		$this->raw = $this->options->get( self::STATE );
		if ( null === $this->raw ) {
			return array();
		}
	 // phpcs:ignore WordPress.WP.AlternativeFunctions.json_decode_json_decode -- Pure PHP queue tests have no WordPress runtime.
		$data = is_string( $this->raw ) && strlen( $this->raw ) <= 614400 ? json_decode( $this->raw, true ) : null;
		if ( ! is_array( $data ) || ! is_int( $data['next_due'] ?? null ) || $data['next_due'] < 1 || ! array_key_exists( 'accepted', $data ) || ! array_key_exists( 'pending', $data ) ) {
			return array( 'invalid' => true );
		}
		if ( null !== $data['pending'] ) {
			$p = $data['pending'];
			if ( ! is_array( $p ) || ! is_string( $p['body'] ?? null ) || strlen( $p['body'] ) > 8192 || ! is_array( $p['snapshot'] ?? null ) || ! in_array( $p['status'] ?? '', array( 'queued', 'sending', 'failed' ), true ) || ! is_int( $p['attempts'] ?? null ) || $p['attempts'] < 0 || $p['attempts'] > 3 || ! is_int( $p['retry_at'] ?? null ) ) {
				return array( 'invalid' => true );
			}
		}
		foreach ( array( $data['accepted'], $data['pending']['snapshot'] ?? null ) as $snapshot ) {
			if ( null === $snapshot ) {
				continue;
			}
			if ( ! is_array( $snapshot ) || ! is_array( $snapshot['identities'] ?? null ) || ! is_array( $snapshot['capped'] ?? null ) ) {
				return array( 'invalid' => true );
			}
			foreach ( DigestSummary::SOURCES as $kind ) {
				$ids = $snapshot['identities'][ $kind ] ?? null;
				if ( ! is_array( $ids ) || count( $ids ) > 1000 || DigestSummary::identities( $ids ) !== $ids || ! is_bool( $snapshot['capped'][ $kind ] ?? null ) ) {
					return array( 'invalid' => true );
				}
			}
		}
		return $data;
	}

	public function tick( array $sources, array $activity, int $now ): string {
		if ( '1' !== $this->options->get( 'amsec_digest_enabled' ) ) {
			return 'off';
		}
		$lock = new WorkerLock( $this->options, 'amsec_digest_lock' );
		if ( ! $lock->acquire( 'digest-' . bin2hex( random_bytes( 8 ) ) ) ) {
			return 'busy';
		}
		try {
			$state = $this->status();
			if ( ! empty( $state['invalid'] ) ) {
				return 'invalid';
			}
			if ( array() === $state ) {
				return $this->save(
					array(
						'next_due' => $now + 604800,
						'accepted' => null,
						'pending'  => null,
					)
				) ? 'waiting' : 'failed';
			}
			if ( $now >= $state['next_due'] ) {
				$summary            = DigestSummary::build( $sources, $activity, $state['accepted'], $now );
				$state['next_due'] += ( intdiv( $now - $state['next_due'], 604800 ) + 1 ) * 604800;
				$state['pending']   = array(
					'body'     => $summary['body'],
					'snapshot' => $summary['snapshot'],
					'status'   => 'queued',
					'attempts' => 0,
					'retry_at' => $now,
				);
			}
			$pending = $state['pending'];
			if ( null === $pending ) {
				return 'waiting';
			}
			if ( 'sending' === $pending['status'] ) {
				return 'uncertain';
			}
			if ( $pending['attempts'] >= 3 ) {
				return 'exhausted';
			}
			if ( $pending['retry_at'] > $now ) {
				return 'waiting';
			}
			$state['pending']['status'] = 'sending';
			++$state['pending']['attempts'];
			$state['pending']['retry_at'] = $now + 3600;
			if ( ! $this->save( $state ) ) {
				return 'failed';
			}
			$accepted = false;
			if ( false !== filter_var( $this->email, FILTER_VALIDATE_EMAIL ) ) {
				try {
					$accepted = (bool) ( $this->send )( $this->email, 'Amazing Security: weekly security digest', $pending['body'] . "\n\nOpen Amazing Security in WordPress:\n" . $this->dashboardUrl );
				} catch ( \Throwable ) {
					return 'uncertain';
				}
			}
			$state['last_attempt'] = array(
				'at'     => $now,
				'status' => $accepted ? 'accepted' : 'failed',
			);
			if ( $accepted ) {
				$state['accepted'] = $pending['snapshot'];
				$state['pending']  = null;
			} else {
				$state['pending']['status'] = 'failed';
			}
			return $this->save( $state ) ? ( $accepted ? 'accepted' : 'failed' ) : 'uncertain';
		} finally {
			$lock->release();
		}
	}

	private function save( array $state ): bool {
	 // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Pure PHP option gateway tests.
		$value = json_encode( $state, JSON_THROW_ON_ERROR );
		if ( strlen( $value ) > 614400 ) {
			return false;
		}
		$saved = null === $this->raw ? $this->options->add( self::STATE, $value ) : ( is_string( $this->raw ) && $this->options->replaceIfSame( self::STATE, $this->raw, $value ) );
		if ( $saved ) {
			$this->raw = $value;
		}
		return $saved;
	}
}
