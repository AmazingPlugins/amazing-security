<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Schedule;

defined( 'ABSPATH' ) || exit;

final class ScheduleStatusRenderer {
	public function render( array $status ): string {
		$state  = (string) ( $status['state'] ?? 'never' );
		$labels = array(
			'never'    => __( 'Not run yet', 'ironlatch-security-scanner' ),
			'running'  => __( 'Running', 'ironlatch-security-scanner' ),
			'complete' => __( 'Completed', 'ironlatch-security-scanner' ),
			'partial'  => __( 'Incomplete', 'ironlatch-security-scanner' ),
			'missed'   => __( 'Missed', 'ironlatch-security-scanner' ),
		);
		$label  = $labels[ $state ] ?? __( 'Unknown', 'ironlatch-security-scanner' );
		$when   = isset( $status['attempted_at'] ) ? gmdate( 'Y-m-d H:i', (int) $status['attempted_at'] ) . ' UTC' : __( 'No attempt recorded', 'ironlatch-security-scanner' );
		$late   = ! empty( $status['overdue'] ) && 'missed' !== $state ? ' ' . __( 'Next run overdue.', 'ironlatch-security-scanner' ) : '';
		return '<div id="ironlatch-schedule" class="ironlatch-schedule-status" role="status"><span>' . esc_html__( 'Daily local hardening', 'ironlatch-security-scanner' ) . '</span><strong>' . esc_html( $label ) . '</strong><small>' . esc_html( $when . $late ) . '</small></div>';
	}

	public function renderSuite( array $status ): string {
		$state  = (string) ( $status['state'] ?? 'never' );
		$labels = array(
			'never'    => __( 'Not run yet', 'ironlatch-security-scanner' ),
			'running'  => __( 'Running', 'ironlatch-security-scanner' ),
			'complete' => __( 'Completed', 'ironlatch-security-scanner' ),
			'partial'  => __( 'Incomplete', 'ironlatch-security-scanner' ),
		);
		$label  = $labels[ $state ] ?? __( 'Unknown', 'ironlatch-security-scanner' );
		$stage  = 'running' === $state ? ' · ' . ( 'integrity' === ( $status['stage'] ?? '' ) ? __( 'Release files', 'ironlatch-security-scanner' ) : __( 'Suspicious files', 'ironlatch-security-scanner' ) ) : '';
		$when   = isset( $status['started_at'] ) ? gmdate( 'Y-m-d H:i', (int) $status['started_at'] ) . ' UTC' : __( 'No attempt recorded', 'ironlatch-security-scanner' );
		return '<div class="ironlatch-schedule-status" role="status"><span>' . esc_html__( 'Daily integrity and file scans', 'ironlatch-security-scanner' ) . '</span><strong>' . esc_html( $label . $stage ) . '</strong><small>' . esc_html( $when ) . '</small></div>';
	}
}
