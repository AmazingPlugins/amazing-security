<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

/** Legacy login panel markup. Live settings live on Log In & Register. */
final class LoginProtectionRenderer {
	public function render( LoginView $view ): string {
		$mode  = array(
			'off'     => 'Off',
			'observe' => 'Observe only',
			'block'   => 'Blocking',
		)[ $view->rateMode ] ?? 'Off';
		$html  = '<section class="amsec-login" aria-labelledby="amsec-login-title"><div class="amsec-login-heading"><div><h2 id="amsec-login-title">Login protection</h2><p>Choose how this site handles repeated sign-in failures. Authenticator and passkey status are reported separately; Amazing Security does not enroll devices.</p></div><strong class="amsec-login-state">' . esc_html( $mode ) . '</strong></div>';
		$html .= '<div class="amsec-login-grid"><div class="amsec-login-panel"><h3>Login attempts</h3><p>Count failed sign-ins using the server connection address. Shared networks can affect several people. Password reset stays available.</p>';
		if ( ! $view->rateSummary['available'] ) {
			$html .= '<p class="notice notice-warning inline">Login counters could not be read. Blocking is unavailable until storage is restored.</p>';
		} else {
			$html .= '<p class="amsec-login-metric">' . esc_html( (string) $view->rateSummary['observed'] ) . ' addresses observed in 24 hours · ' . esc_html( (string) $view->rateSummary['blocked'] ) . ' currently blocked</p>';
		}
		$html .= '<form method="post" action="' . esc_url( $view->formAction ) . '"><input type="hidden" name="action" value="amsec_login_settings"><input type="hidden" name="_wpnonce" value="' . esc_attr( $view->nonces['settings'] ?? '' ) . '">';
		$html .= '<label for="amsec-rate-mode">Response to repeated failures</label><select id="amsec-rate-mode" name="rate_mode">';
		foreach ( array(
			'off'     => 'Off',
			'observe' => 'Observe only',
			'block'   => 'Block after five failures for 15 minutes',
		) as $value => $label ) {
			$html .= '<option value="' . esc_attr( $value ) . '"' . ( $view->rateMode === $value ? ' selected' : '' ) . '>' . esc_html( $label ) . '</option>';
		}
		$html .= '</select><p class="description">Blocking requires an explicit choice. Turn it off here or with WP-CLI if you are locked out.</p>';
		$html .= '<label class="amsec-check"><input type="checkbox" name="xmlrpc_disabled" value="1"' . ( $view->xmlRpcDisabled ? ' checked' : '' ) . '> Disable authenticated XML-RPC methods</label>';
		$html .= '<p class="description">May affect Jetpack or mobile publishing. Pingbacks and other unauthenticated methods remain available.</p>';
		$html .= '<label class="amsec-check"><input type="checkbox" name="erase_on_uninstall" value="1"' . ( $view->eraseOnUninstall ? ' checked' : '' ) . '> Erase all Amazing Security data on uninstall</label>';
		$html .= '<p><button class="button button-primary" type="submit">Save login settings</button></p></form></div>';
		$html .= '<div class="amsec-login-panel"><h3>Authenticator and passkeys</h3><p>Account: <strong>' . esc_html( $view->username ) . '</strong></p>';
		$html .= '<p>Check status under Log In &amp; Register. Amazing Security does not enroll devices or store backup codes. Use a dedicated plugin such as Two Factor when you want app codes or passkeys.</p>';
		$html .= '<p><a class="button" href="' . esc_url( admin_url( 'admin.php?page=amsec-accounts#verification' ) ) . '">Open authenticator status</a> ';
		$html .= '<a class="button" href="' . esc_url( admin_url( 'admin.php?page=amsec-accounts#passkeys' ) ) . '">Open passkey status</a></p>';
		$html .= '<p class="description">This protects interactive WordPress and tested WooCommerce sign-ins. Application passwords and unsupported custom forms need separate review.</p></div></div></section>';
		return $html;
	}
}
