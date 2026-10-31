<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Alerts;

defined( 'ABSPATH' ) || exit;

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

	public function sendNew( array $ids, int $now, string $source = 'general', bool $complete = true ): string {
		if ( ! $this->enabled() ) {
			return 'off';
		}
		$ids  = array_values( array_unique( array_filter( $ids, static fn( mixed $id ): bool => is_string( $id ) && (bool) preg_match( '/^[a-zA-Z0-9-]{1,80}$/D', $id ) ) ) );
		$lock = new WorkerLock( $this->options, 'amsec_alert_lock' );
		if ( ! $lock->acquire( 'mail-' . $now ) ) {
			return 'busy';
		}
		try {
			$state    = $this->status();
			$active   = is_array( $state['active'] ?? null ) ? $state['active'] : array();
			$previous = is_array( $active[ $source ] ?? null ) ? $active[ $source ] : array();
			if ( ! $complete ) {
				$ids = array_values( array_unique( array_merge( $ids, $previous ) ) );
			}
			$pending           = is_array( $state['pending'] ?? null ) ? $state['pending'] : array();
			$pending           = array_values( array_filter( $pending, static fn( string $id ): bool => ! in_array( $id, $previous, true ) || in_array( $id, $ids, true ) ) );
			$new               = array_values( array_diff( $ids, $previous ) );
			$active[ $source ] = $ids;
			$state['active']   = $active;
			$state['pending']  = array_values( array_unique( array_merge( $pending, $new ) ) );
			return $this->deliver( $state, $now );
		} finally {
			$lock->release();
		}
	}

	public function retry( int $now ): string {
		if ( ! $this->enabled() ) {
			return 'off';
		}
		$lock = new WorkerLock( $this->options, 'amsec_alert_lock' );
		if ( ! $lock->acquire( 'mail-retry-' . $now ) ) {
			return 'busy';
		}
		try {
			return $this->deliver( $this->status(), $now );
		} finally {
			$lock->release();
		}
	}

	private function enabled(): bool {
		return '1' === $this->options->get( 'amsec_alerts_enabled' );
	}

	private function deliver( array $state, int $now ): string {
		$pending = is_array( $state['pending'] ?? null ) ? $state['pending'] : array();
		if ( array() === $pending ) {
			$this->save( $state );
			return 'none';
		}
		$batch    = array_slice( $pending, 0, 50 );
		$accepted = false;
		if ( false !== filter_var( $this->email, FILTER_VALIDATE_EMAIL ) ) {
			$body = "New security findings need review.\n\nFinding IDs:\n" . implode( "\n", $batch ) . "\n\nOpen the AmSec Security Scanner dashboard:\n" . $this->dashboardUrl;
			try {
				$accepted = (bool) ( $this->send )( $this->email, 'AmSec Security Scanner: findings need review', $body );
			} catch ( Throwable ) {
				$accepted = false;
			}
		}
		$state['pending']      = $accepted ? array_slice( $pending, 50 ) : $pending;
		$state['last_attempt'] = array(
			'at'     => $now,
			'status' => $accepted ? 'accepted' : 'failed',
			'count'  => count( $batch ),
		);
		$state['failures']     = $accepted ? 0 : min( 3, (int) ( $state['failures'] ?? 0 ) + 1 );
		if ( ! $this->save( $state ) ) {
			return 'failed';
		}
		if ( array() !== $state['pending'] && ( $accepted || $state['failures'] < 3 ) && function_exists( 'wp_next_scheduled' ) && ! wp_next_scheduled( 'amsec_alert_retry' ) ) {
			wp_schedule_single_event( time() + ( $accepted ? 60 : 3600 ), 'amsec_alert_retry' );
		}
		return $accepted ? 'accepted' : 'failed';
	}

	private function save( array $state ): bool {
		// phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Pure PHP option gateway tests run without WordPress.
		return $this->options->set( self::STATE, json_encode( $state, JSON_THROW_ON_ERROR ) );
	}
}
