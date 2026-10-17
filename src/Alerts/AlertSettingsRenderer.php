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
		$detail = __( 'No finding email attempted yet.', 'amazing-security' );
		if ( is_array( $last ) && isset( $last['status'], $last['at'] ) ) {
			$label  = 'accepted' === $last['status'] ? __( 'Accepted for sending', 'amazing-security' ) : __( 'Sending failed', 'amazing-security' );
			$detail = sprintf(
					/* translators: 1: last email attempt outcome; 2: UTC date and time of the attempt. */
				__( '%1$s at %2$s UTC. This does not confirm inbox delivery.', 'amazing-security' ),
				$label,
				gmdate( 'Y-m-d H:i', (int) $last['at'] )
			);
		}
		$configured = ! empty( $mail['configured'] );
		$html       = '<section class="amsec-alert-settings" aria-labelledby="amsec-alerts"><h2 id="amsec-alerts">' . esc_html__( 'Finding emails', 'amazing-security' ) . '</h2>';
		$html      .= '<p>' . esc_html__( 'Get an email about new selected file findings, changed published files, or confirmed high and critical vulnerabilities. The message contains finding IDs and a link to this dashboard. It uses WordPress mail to the administrator email.', 'amazing-security' ) . '</p>';
		if ( array() !== $mail && ! $configured ) {
			$html .= '<p class="notice notice-warning inline">' . esc_html__( 'Email is not configured. Finding emails will not send until the WordPress admin email is valid.', 'amazing-security' ) . '</p>';
		}
		$html .= '<form action="' . esc_url( $postUrl ) . '" method="post"><input type="hidden" name="action" value="amsec_alert_settings"><input type="hidden" name="_wpnonce" value="' . esc_attr( $nonce ) . '">';
		$html .= '<fieldset><legend>' . esc_html__( 'Finding emails', 'amazing-security' ) . '</legend>';
		$html .= '<label><input type="radio" name="enabled" value="1"' . ( $enabled ? ' checked' : '' ) . '> ' . esc_html__( 'On', 'amazing-security' ) . '</label>';
		$html .= '<label><input type="radio" name="enabled" value="0"' . ( $enabled ? '' : ' checked' ) . '> ' . esc_html__( 'Off', 'amazing-security' ) . '</label>';
		$html .= '</fieldset>';
		if ( ! $configured ) {
			$html .= '<p class="description">' . esc_html__( 'Even if On is saved, WordPress will not send until the admin email is valid.', 'amazing-security' ) . '</p>';
		}
		$html .= '<button class="button" type="submit">' . esc_html__( 'Save finding email setting', 'amazing-security' ) . '</button></form>';
		$html .= '<p class="amsec-muted">' . esc_html( $detail ) . '</p></section>';
		return $html;
	}
}
