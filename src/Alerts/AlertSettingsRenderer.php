<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Alerts;

final class AlertSettingsRenderer {
	public function render( bool $enabled, array $status, string $postUrl, string $nonce ): string {
		$last   = $status['last_attempt'] ?? null;
		$detail = 'No finding email attempted yet.';
		if ( is_array( $last ) && isset( $last['status'], $last['at'] ) ) {
			$label  = 'accepted' === $last['status'] ? 'Accepted for sending' : 'Sending failed';
			$detail = $label . ' at ' . gmdate( 'Y-m-d H:i', (int) $last['at'] ) . ' UTC. This does not confirm inbox delivery.';
		}
		return '<section class="amsec-alert-settings" aria-labelledby="amsec-alerts"><h2 id="amsec-alerts">Email alerts</h2><p>Get an email about new selected file findings, changed published files, or confirmed high and critical vulnerabilities. The message contains finding IDs and a link to this dashboard.</p><form action="' . esc_url( $postUrl ) . '" method="post"><input type="hidden" name="action" value="amsec_alert_settings"><input type="hidden" name="_wpnonce" value="' . esc_attr( $nonce ) . '"><fieldset><legend>Finding emails</legend><label><input type="radio" name="enabled" value="1"' . ( $enabled ? ' checked' : '' ) . '> On</label><label><input type="radio" name="enabled" value="0"' . ( $enabled ? '' : ' checked' ) . '> Off</label></fieldset><button class="button" type="submit">Save alert setting</button></form><p class="amsec-muted">' . esc_html( $detail ) . '</p></section>';
	}
}
