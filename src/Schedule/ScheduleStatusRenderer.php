<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Schedule;

defined( 'ABSPATH' ) || exit;

final class ScheduleStatusRenderer {
	public function render( array $status ): string {
		$state  = (string) ( $status['state'] ?? 'never' );
		$labels = array(
			'never'    => __( 'Not run yet', 'amazing-security-scanner' ),
			'running'  => __( 'Running', 'amazing-security-scanner' ),
			'complete' => __( 'Completed', 'amazing-security-scanner' ),
			'partial'  => __( 'Incomplete', 'amazing-security-scanner' ),
			'missed'   => __( 'Missed', 'amazing-security-scanner' ),
		);
		$label  = $labels[ $state ] ?? __( 'Unknown', 'amazing-security-scanner' );
		$when   = isset( $status['attempted_at'] ) ? gmdate( 'Y-m-d H:i', (int) $status['attempted_at'] ) . ' UTC' : __( 'No attempt recorded', 'amazing-security-scanner' );
		$late   = ! empty( $status['overdue'] ) && 'missed' !== $state ? ' ' . __( 'Next run overdue.', 'amazing-security-scanner' ) : '';
		return '<div id="amsec-schedule" class="amsec-schedule-status" role="status"><span>' . esc_html__( 'Daily local hardening', 'amazing-security-scanner' ) . '</span><strong>' . esc_html( $label ) . '</strong><small>' . esc_html( $when . $late ) . '</small></div>';
	}

	public function renderSuite( array $status ): string {
		$state  = (string) ( $status['state'] ?? 'never' );
		$labels = array(
			'never'    => __( 'Not run yet', 'amazing-security-scanner' ),
			'running'  => __( 'Running', 'amazing-security-scanner' ),
			'complete' => __( 'Completed', 'amazing-security-scanner' ),
			'partial'  => __( 'Incomplete', 'amazing-security-scanner' ),
		);
		$label  = $labels[ $state ] ?? __( 'Unknown', 'amazing-security-scanner' );
		$stage  = 'running' === $state ? ' · ' . ( 'integrity' === ( $status['stage'] ?? '' ) ? __( 'Release files', 'amazing-security-scanner' ) : __( 'Suspicious files', 'amazing-security-scanner' ) ) : '';
		$when   = isset( $status['started_at'] ) ? gmdate( 'Y-m-d H:i', (int) $status['started_at'] ) . ' UTC' : __( 'No attempt recorded', 'amazing-security-scanner' );
		return '<div class="amsec-schedule-status" role="status"><span>' . esc_html__( 'Daily integrity and file scans', 'amazing-security-scanner' ) . '</span><strong>' . esc_html( $label . $stage ) . '</strong><small>' . esc_html( $when ) . '</small></div>';
	}
}
