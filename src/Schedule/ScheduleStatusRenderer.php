<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Schedule;

final class ScheduleStatusRenderer {
	public function render( array $status ): string {
		$state  = (string) ( $status['state'] ?? 'never' );
		$labels = array(
			'never'    => 'Not run yet',
			'running'  => 'Running',
			'complete' => 'Completed',
			'partial'  => 'Incomplete',
			'missed'   => 'Missed',
		);
		$label  = $labels[ $state ] ?? 'Unknown';
		$when   = isset( $status['attempted_at'] ) ? gmdate( 'Y-m-d H:i', (int) $status['attempted_at'] ) . ' UTC' : 'No attempt recorded';
		$late   = ! empty( $status['overdue'] ) && 'missed' !== $state ? ' Next run overdue.' : '';
		return '<div class="amsec-schedule-status" role="status"><span>Daily local hardening</span><strong>' . esc_html( $label ) . '</strong><small>' . esc_html( $when . $late ) . '</small></div>';
	}

	public function renderSuite( array $status ): string {
		$state  = (string) ( $status['state'] ?? 'never' );
		$labels = array(
			'never'    => 'Not run yet',
			'running'  => 'Running',
			'complete' => 'Completed',
			'partial'  => 'Incomplete',
		);
		$label  = $labels[ $state ] ?? 'Unknown';
		$stage  = 'running' === $state ? ' · ' . ( 'integrity' === ( $status['stage'] ?? '' ) ? 'Release files' : 'Suspicious files' ) : '';
		$when   = isset( $status['started_at'] ) ? gmdate( 'Y-m-d H:i', (int) $status['started_at'] ) . ' UTC' : 'No attempt recorded';
		return '<div class="amsec-schedule-status" role="status"><span>Daily integrity and file scans</span><strong>' . esc_html( $label . $stage ) . '</strong><small>' . esc_html( $when ) . '</small></div>';
	}
}
