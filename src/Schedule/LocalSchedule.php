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

	public function __construct( private readonly OptionGateway $options, ?callable $run = null ) {
		$this->run = Closure::fromCallable( $run ?? static fn(): ScanRun => ( new LocalHardeningScanService() )->run() );
	}

	public function status( int $now ): array {
		$raw  = $this->options->get( self::STATE_OPTION );
		$data = is_string( $raw ) ? json_decode( $raw, true ) : null;
		if ( ! is_array( $data ) || ! isset( $data['attempted_at'], $data['state'] ) ) {
			return array(
				'state'        => 'never',
				'attempted_at' => null,
				'next_due'     => null,
			);
		}
		$attemptedAt = (int) $data['attempted_at'];
		$nextDue     = $attemptedAt + 86400;
		$state       = (string) $data['state'];
		if ( $now > $nextDue + 3600 && 'running' !== $state ) {
			$state = 'missed';
		} elseif ( 'running' === $state && $now > $attemptedAt + 3600 ) {
			$state = 'partial';
		}
		return array(
			'state'        => $state,
			'attempted_at' => $attemptedAt,
			'next_due'     => $nextDue,
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
