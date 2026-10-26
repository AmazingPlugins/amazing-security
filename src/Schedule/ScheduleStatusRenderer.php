<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Schedule;

defined( 'ABSPATH' ) || exit;

final class ScheduleStatusRenderer {
	public function render( array $status ): string {
		$state  = (string) ( $status['state'] ?? 'never' );
		$labels = array(
			'never'    => __( 'Not run yet', 'amazingplugins-security-scanner' ),
			'running'  => __( 'Running', 'amazingplugins-security-scanner' ),
			'complete' => __( 'Completed', 'amazingplugins-security-scanner' ),
			'partial'  => __( 'Incomplete', 'amazingplugins-security-scanner' ),
			'missed'   => __( 'Missed', 'amazingplugins-security-scanner' ),
		);
		$label  = $labels[ $state ] ?? __( 'Unknown', 'amazingplugins-security-scanner' );
		$when   = isset( $status['attempted_at'] ) ? gmdate( 'Y-m-d H:i', (int) $status['attempted_at'] ) . ' UTC' : __( 'No attempt recorded', 'amazingplugins-security-scanner' );
		$late   = ! empty( $status['overdue'] ) && 'missed' !== $state ? ' ' . __( 'Next run overdue.', 'amazingplugins-security-scanner' ) : '';
		return '<div id="amsec-schedule" class="amsec-schedule-status" role="status"><span>' . esc_html__( 'Daily local hardening', 'amazingplugins-security-scanner' ) . '</span><strong>' . esc_html( $label ) . '</strong><small>' . esc_html( $when . $late ) . '</small></div>';
	}

	public function renderSuite( array $status ): string {
		$state  = (string) ( $status['state'] ?? 'never' );
		$labels = array(
			'never'    => __( 'Not run yet', 'amazingplugins-security-scanner' ),
			'running'  => __( 'Running', 'amazingplugins-security-scanner' ),
			'complete' => __( 'Completed', 'amazingplugins-security-scanner' ),
			'partial'  => __( 'Incomplete', 'amazingplugins-security-scanner' ),
		);
		$label  = $labels[ $state ] ?? __( 'Unknown', 'amazingplugins-security-scanner' );
		$stage  = 'running' === $state ? ' · ' . ( 'integrity' === ( $status['stage'] ?? '' ) ? __( 'Release files', 'amazingplugins-security-scanner' ) : __( 'Suspicious files', 'amazingplugins-security-scanner' ) ) : '';
		$when   = isset( $status['started_at'] ) ? gmdate( 'Y-m-d H:i', (int) $status['started_at'] ) . ' UTC' : __( 'No attempt recorded', 'amazingplugins-security-scanner' );
		return '<div class="amsec-schedule-status" role="status"><span>' . esc_html__( 'Daily integrity and file scans', 'amazingplugins-security-scanner' ) . '</span><strong>' . esc_html( $label . $stage ) . '</strong><small>' . esc_html( $when ) . '</small></div>';
	}
}
