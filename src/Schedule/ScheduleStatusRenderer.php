<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Schedule;

defined( 'ABSPATH' ) || exit;

final class ScheduleStatusRenderer {
	public function render( array $status ): string {
		$state  = (string) ( $status['state'] ?? 'never' );
		$labels = array(
			'never'    => __( 'Not run yet', 'amsec-security-scanner' ),
			'running'  => __( 'Running', 'amsec-security-scanner' ),
			'complete' => __( 'Completed', 'amsec-security-scanner' ),
			'partial'  => __( 'Incomplete', 'amsec-security-scanner' ),
			'missed'   => __( 'Missed', 'amsec-security-scanner' ),
		);
		$label  = $labels[ $state ] ?? __( 'Unknown', 'amsec-security-scanner' );
		$when   = isset( $status['attempted_at'] ) ? gmdate( 'Y-m-d H:i', (int) $status['attempted_at'] ) . ' UTC' : __( 'No attempt recorded', 'amsec-security-scanner' );
		$late   = ! empty( $status['overdue'] ) && 'missed' !== $state ? ' ' . __( 'Next run overdue.', 'amsec-security-scanner' ) : '';
		return '<div id="amsec-schedule" class="amsec-schedule-status" role="status"><span>' . esc_html__( 'Daily local hardening', 'amsec-security-scanner' ) . '</span><strong>' . esc_html( $label ) . '</strong><small>' . esc_html( $when . $late ) . '</small></div>';
	}

	public function renderSuite( array $status ): string {
		$state  = (string) ( $status['state'] ?? 'never' );
		$labels = array(
			'never'    => __( 'Not run yet', 'amsec-security-scanner' ),
			'running'  => __( 'Running', 'amsec-security-scanner' ),
			'complete' => __( 'Completed', 'amsec-security-scanner' ),
			'partial'  => __( 'Incomplete', 'amsec-security-scanner' ),
		);
		$label  = $labels[ $state ] ?? __( 'Unknown', 'amsec-security-scanner' );
		$stage  = 'running' === $state ? ' · ' . ( 'integrity' === ( $status['stage'] ?? '' ) ? __( 'Release files', 'amsec-security-scanner' ) : __( 'Suspicious files', 'amsec-security-scanner' ) ) : '';
		$when   = isset( $status['started_at'] ) ? gmdate( 'Y-m-d H:i', (int) $status['started_at'] ) . ' UTC' : __( 'No attempt recorded', 'amsec-security-scanner' );
		return '<div class="amsec-schedule-status" role="status"><span>' . esc_html__( 'Daily integrity and file scans', 'amsec-security-scanner' ) . '</span><strong>' . esc_html( $label . $stage ) . '</strong><small>' . esc_html( $when ) . '</small></div>';
	}
}
