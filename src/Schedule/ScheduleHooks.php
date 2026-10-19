<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Schedule;

defined( 'ABSPATH' ) || exit;

use Closure;

final class ScheduleHooks {
	private readonly Closure $next;
	private readonly Closure $schedule;
	private readonly Closure $clear;
	private readonly Closure $started;

	public function __construct( ?callable $next = null, ?callable $schedule = null, ?callable $clear = null, ?callable $started = null ) {
		$this->next     = Closure::fromCallable( $next ?? static fn(): bool => false !== wp_next_scheduled( 'amsec_local_daily_scan' ) );
		$this->schedule = Closure::fromCallable( $schedule ?? static fn( int $when, string $recurrence, string $hook ): bool => wp_schedule_event( $when, $recurrence, $hook ) );
		$this->clear    = Closure::fromCallable( $clear ?? static fn( string $hook ): int|false => wp_clear_scheduled_hook( $hook ) );
		$this->started  = Closure::fromCallable( $started ?? static fn(): bool => false !== get_option( 'amazing_security_latest_run', false ) );
	}

	public function ensure(): void {
		// The daily scan, and its WordPress.org lookups, start only after an administrator's first Scan.
		if ( ( $this->started )() && ! ( $this->next )() ) {
			( $this->schedule )( time() + 60, 'daily', 'amsec_local_daily_scan' );
		}
	}

	public function clear(): void {
		foreach ( array( 'amsec_local_daily_scan', 'amsec_integrity_tick', 'amsec_file_tick', 'amsec_local_code_tick', 'amsec_vuln_tick', 'amsec_alert_retry' ) as $hook ) {
			( $this->clear )( $hook );
		}
	}
}
