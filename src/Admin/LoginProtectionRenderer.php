<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

final class LoginProtectionRenderer {
	public function render( LoginView $view ): string {
		$mode  = array(
			'off'     => 'Off',
			'observe' => 'Observe only',
			'block'   => 'Blocking',
		)[ $view->rateMode ] ?? 'Off';
		$html  = '<section class="amsec-login" aria-labelledby="amsec-login-title"><div class="amsec-login-heading"><div><h2 id="amsec-login-title">Login protection</h2><p>Choose how this site handles repeated sign-in failures and administrator verification.</p></div><strong class="amsec-login-state">' . esc_html( $mode ) . '</strong></div>';
		$html .= '<div class="amsec-login-grid"><div class="amsec-login-panel"><h3>Login attempts</h3><p>Count failed sign-ins using the server connection address. Shared networks can affect several people. Password reset stays available.</p>';
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
		$html .= '<label class="amsec-check"><input type="checkbox" name="erase_on_uninstall" value="1"' . ( $view->eraseOnUninstall ? ' checked' : '' ) . '> Erase login protection data on uninstall</label>';
		$html .= '<p><button class="button button-primary" type="submit">Save login settings</button></p></form></div>';
		$html .= '<div class="amsec-login-panel"><h3>Administrator verification</h3><p>Account: <strong>' . esc_html( $view->username ) . '</strong></p>';
		if ( ! $view->https ) {
			$html .= '<p class="notice notice-warning inline">Set up HTTPS for wp-admin before enrolling a verification device.</p>';
		} elseif ( ! $view->enrolled ) {
			$html .= '<p>No verification device enrolled for this administrator.</p>' . $this->postButton( $view, 'begin', 'amsec_totp_begin', 'Set up verification codes' );
		} else {
			$html .= '<p>Verification is on for this administrator. Save your recovery codes outside this site.</p>';
			$html .= $this->factorForm( $view, 'regenerate', 'amsec_totp_regenerate', 'Replace recovery codes' );
			$html .= $this->factorForm( $view, 'disable', 'amsec_totp_disable', 'Turn off verification' );
		}
		$html .= '<p class="description">This protects interactive WordPress and tested WooCommerce sign-ins. Application passwords and unsupported custom forms need separate review.</p></div></div></section>';
		return $html;
	}

	private function postButton( LoginView $view, string $nonceKey, string $action, string $label ): string {
		return '<form method="post" action="' . esc_url( $view->formAction ) . '"><input type="hidden" name="action" value="' . esc_attr( $action ) . '"><input type="hidden" name="_wpnonce" value="' . esc_attr( $view->nonces[ $nonceKey ] ?? '' ) . '"><button class="button" type="submit">' . esc_html( $label ) . '</button></form>';
	}

	private function factorForm( LoginView $view, string $nonceKey, string $action, string $label ): string {
		return '<form class="amsec-factor-form" method="post" action="' . esc_url( $view->formAction ) . '"><input type="hidden" name="action" value="' . esc_attr( $action ) . '"><input type="hidden" name="_wpnonce" value="' . esc_attr( $view->nonces[ $nonceKey ] ?? '' ) . '"><label>Current verification or recovery code <input name="factor" type="text" inputmode="numeric" autocomplete="one-time-code" required></label><label>Current WordPress password <input name="password" type="password" autocomplete="current-password" required></label><button class="button" type="submit">' . esc_html( $label ) . '</button></form>';
	}
}
