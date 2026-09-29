<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Alerts;

use AmazingPlugins\Security\Integrity\OptionGateway;
use AmazingPlugins\Security\Integrity\WorkerLock;
use Closure;
use Throwable;

final class AlertDelivery {
	private const STATE = 'amsec_alert_state';
	private readonly Closure $send;

	public function __construct( private readonly OptionGateway $options, callable $send, private readonly string $email, private readonly string $dashboardUrl ) {
		$this->send = Closure::fromCallable( $send );
	}

	public function status(): array {
		$raw  = $this->options->get( self::STATE );
		$data = is_string( $raw ) ? json_decode( $raw, true ) : null;
		return is_array( $data ) ? $data : array();
	}

	public function sendNew( array $ids, int $now ): string {
		if ( '0' === $this->options->get( 'amsec_alerts_enabled' ) ) {
			return 'off';
		}
		$ids = array_values( array_unique( array_filter( $ids, static fn( mixed $id ): bool => is_string( $id ) && (bool) preg_match( '/^[a-zA-Z0-9-]{1,80}$/D', $id ) ) ) );
		if ( array() === $ids ) {
			return 'none';
		}
		$lock = new WorkerLock( $this->options, 'amsec_alert_lock' );
		if ( ! $lock->acquire( 'mail-' . $now ) ) {
			return 'busy';
		}
		try {
			$state = $this->status();
			$sent  = is_array( $state['sent'] ?? null ) ? $state['sent'] : array();
			$sent  = array_filter( $sent, static fn( mixed $at ): bool => is_int( $at ) && $at >= $now - 90 * 86400 );
			$new   = array_slice( array_values( array_filter( $ids, static fn( string $id ): bool => ! isset( $sent[ $id ] ) ) ), 0, 50 );
			if ( array() === $new ) {
				return 'none';
			}
			if ( false === filter_var( $this->email, FILTER_VALIDATE_EMAIL ) ) {
				return 'failed';
			}
			$body = "New security findings need review.\n\nFinding IDs:\n" . implode( "\n", $new ) . "\n\nOpen the Amazing Security dashboard:\n" . $this->dashboardUrl;
			try {
				$accepted = ( $this->send )( $this->email, 'Amazing Security: findings need review', $body );
			} catch ( Throwable ) {
				$accepted = false;
			}
			if ( $accepted ) {
				foreach ( $new as $id ) {
					$sent[ $id ] = $now;
				}
				$sent = array_slice( $sent, -250, null, true );
			}
			$state = array(
				'sent'         => $sent,
				'last_attempt' => array(
					'at'     => $now,
					'status' => $accepted ? 'accepted' : 'failed',
					'count'  => count( $new ),
				),
			);
			// phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Pure PHP option gateway tests run without WordPress.
			$encoded = json_encode( $state, JSON_THROW_ON_ERROR );
			return $this->options->set( self::STATE, $encoded ) ? ( $accepted ? 'accepted' : 'failed' ) : 'failed';
		} finally {
			$lock->release();
		}
	}
}
