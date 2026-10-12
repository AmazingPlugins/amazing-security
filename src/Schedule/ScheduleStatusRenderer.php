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
		return '<div id="amsec-schedule" class="amsec-schedule-status" role="status"><span>Daily local hardening</span><strong>' . esc_html( $label ) . '</strong><small>' . esc_html( $when . $late ) . '</small></div>';
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

	public function renderReleaseToggle( bool $enabled, string $actionUrl, string $nonce ): string {
		$html  = '<form class="amsec-schedule-release" method="post" action="' . esc_url( $actionUrl ) . '">';
		$html .= '<input type="hidden" name="action" value="amsec_daily_release_check"><input type="hidden" name="_wpnonce" value="' . esc_attr( $nonce ) . '">';
		$html .= '<h3>' . esc_html__( 'Daily release file comparison', 'amazing-security' ) . '</h3>';
		$html .= '<p>' . esc_html__( 'Off by default. When on, the daily check compares WordPress core, plugin and theme files with the published WordPress.org release. This contacts api.wordpress.org and downloads.wordpress.org and sends the WordPress version plus the slugs and versions being checked. No file contents are sent. When off, the daily check runs only on this server. You can still start a release comparison yourself at any time.', 'amazing-security' ) . '</p>';
		$html .= '<p><input type="hidden" name="enabled" value="0"><label><input type="checkbox" name="enabled" value="1"' . ( $enabled ? ' checked' : '' ) . '> ' . esc_html__( 'Compare release files with WordPress.org every day', 'amazing-security' ) . '</label> ';
		$html .= '<button type="submit" class="button">' . esc_html__( 'Save', 'amazing-security' ) . '</button></p></form>';
		return $html;
	}
}
