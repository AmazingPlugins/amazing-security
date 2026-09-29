<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Schedule;

use AmazingPlugins\Security\Integrity\OptionGateway;
use AmazingPlugins\Security\Integrity\WorkerLock;
use AmazingPlugins\Security\Scan\LocalHardeningScanService;
use AmazingPlugins\Security\Scan\ScanRun;
use Closure;
use RuntimeException;
use Throwable;

final class LocalSchedule {
	private const STATE_OPTION = 'amsec_local_schedule_state';
	private readonly Closure $run;
	private readonly Closure $nextEvent;

	public function __construct( private readonly OptionGateway $options, ?callable $run = null, ?callable $nextEvent = null ) {
		$this->run       = Closure::fromCallable( $run ?? static fn(): ScanRun => ( new LocalHardeningScanService() )->run() );
		$this->nextEvent = Closure::fromCallable( $nextEvent ?? static fn(): int|false => function_exists( 'wp_next_scheduled' ) ? wp_next_scheduled( 'amsec_local_daily_scan' ) : false );
	}

	public function status( int $now ): array {
		$raw  = $this->options->get( self::STATE_OPTION );
		$data = is_string( $raw ) ? json_decode( $raw, true ) : null;
		if ( ! is_array( $data ) || ! isset( $data['attempted_at'], $data['state'] ) ) {
			$due = ( $this->nextEvent )();
			return array(
				'state'        => is_int( $due ) && $now > $due + 3600 ? 'missed' : 'never',
				'attempted_at' => null,
				'next_due'     => is_int( $due ) ? $due : null,
				'overdue'      => is_int( $due ) && $now > $due + 3600,
			);
		}
		$attemptedAt = (int) $data['attempted_at'];
		$nextDue     = $attemptedAt + 86400;
		$state       = (string) $data['state'];
		$overdue     = $now > $nextDue + 3600;
		if ( $overdue && 'complete' === $state ) {
			$state = 'missed';
		} elseif ( 'running' === $state && $now > $attemptedAt + 3600 ) {
			$state = 'partial';
		}
		return array(
			'state'        => $state,
			'attempted_at' => $attemptedAt,
			'next_due'     => $nextDue,
			'overdue'      => $overdue,
		);
	}

	public function tick( int $now ): bool {
		$lock = new WorkerLock( $this->options, 'amsec_schedule_lock' );
		if ( ! $lock->acquire( 'local-' . $now ) ) {
			return false;
		}
		try {
			$this->save( $now, 'running' );
			$run = ( $this->run )();
			$this->save( $now, $run->partial ? 'partial' : 'complete' );
			return true;
		} catch ( Throwable ) {
			try {
				$this->save( $now, 'partial' );
			} catch ( Throwable ) {
				// A failed state write must not escape WP-Cron or claim completion.
				return false;
			}
			return false;
		} finally {
			$lock->release();
		}
	}

	private function save( int $attemptedAt, string $state ): void {
		if ( ! $this->options->set(
			self::STATE_OPTION,
			// phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Pure PHP schedule state shares the option gateway with WordPress.
			json_encode(
				array(
					'attempted_at' => $attemptedAt,
					'state'        => $state,
				),
				JSON_THROW_ON_ERROR
			)
		) ) {
			throw new RuntimeException( 'Schedule state could not be saved.' );
		}
	}
}
