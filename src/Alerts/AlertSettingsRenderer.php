<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Alerts;

defined( 'ABSPATH' ) || exit;

final class AlertSettingsRenderer {
	/**
	 * @param array<string, mixed>               $status
	 * @param array{email?: string, configured?: bool, summary?: string} $mail
	 */
	public function render( bool $enabled, array $status, string $postUrl, string $nonce, array $mail = array() ): string {
		$last   = $status['last_attempt'] ?? null;
		$detail = 'No finding email attempted yet.';
		if ( is_array( $last ) && isset( $last['status'], $last['at'] ) ) {
			$label  = 'accepted' === $last['status'] ? 'Accepted for sending' : 'Sending failed';
			$detail = $label . ' at ' . gmdate( 'Y-m-d H:i', (int) $last['at'] ) . ' UTC. This does not confirm inbox delivery.';
		}
		$configured = ! empty( $mail['configured'] );
		$html       = '<section class="amsec-alert-settings" aria-labelledby="amsec-alerts"><h2 id="amsec-alerts">Finding emails</h2>';
		$html      .= '<p>Get an email about new selected file findings, changed published files, or confirmed high and critical vulnerabilities. The message contains finding IDs and a link to this dashboard. It uses WordPress mail to the administrator email.</p>';
		if ( array() !== $mail && ! $configured ) {
			$html .= '<p class="notice notice-warning inline">Email is not configured. Finding emails will not send until the WordPress admin email is valid.</p>';
		}
		$html .= '<form action="' . esc_url( $postUrl ) . '" method="post"><input type="hidden" name="action" value="amsec_alert_settings"><input type="hidden" name="_wpnonce" value="' . esc_attr( $nonce ) . '">';
		$html .= '<fieldset><legend>Finding emails</legend>';
		$html .= '<label><input type="radio" name="enabled" value="1"' . ( $enabled ? ' checked' : '' ) . '> On</label>';
		$html .= '<label><input type="radio" name="enabled" value="0"' . ( $enabled ? '' : ' checked' ) . '> Off</label>';
		$html .= '</fieldset>';
		if ( ! $configured ) {
			$html .= '<p class="description">Even if On is saved, WordPress will not send until the admin email is valid.</p>';
		}
		$html .= '<button class="button" type="submit">Save finding email setting</button></form>';
		$html .= '<p class="amsec-muted">' . esc_html( $detail ) . '</p></section>';
		return $html;
	}
}
