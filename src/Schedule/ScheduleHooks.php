<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Schedule;

use Closure;

final class ScheduleHooks {
	private readonly Closure $next;
	private readonly Closure $schedule;
	private readonly Closure $clear;

	public function __construct( ?callable $next = null, ?callable $schedule = null, ?callable $clear = null ) {
		$this->next     = Closure::fromCallable( $next ?? static fn(): bool => false !== wp_next_scheduled( 'amsec_local_daily_scan' ) );
		$this->schedule = Closure::fromCallable( $schedule ?? static fn( int $when, string $recurrence, string $hook ): bool => wp_schedule_event( $when, $recurrence, $hook ) );
		$this->clear    = Closure::fromCallable( $clear ?? static fn(): int|false => wp_clear_scheduled_hook( 'amsec_local_daily_scan' ) );
	}

	public function ensure(): void {
		if ( ! ( $this->next )() ) {
			( $this->schedule )( time() + 60, 'daily', 'amsec_local_daily_scan' );
		}
	}

	public function clear(): void {
		( $this->clear )();
	}
}
