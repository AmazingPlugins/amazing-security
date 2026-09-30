<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Sessions;

final class SessionPage {
	public function register(): void {
		add_submenu_page( 'amazing-security', 'Account sessions', 'Sessions', 'manage_options', 'amsec-sessions', array( $this, 'render' ) );
	}

	public function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You cannot manage account sessions.', 'amazing-security' ), '', array( 'response' => 403 ) );
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only account selection with permission checks.
		$id = isset( $_GET['user_id'] ) && is_scalar( $_GET['user_id'] ) ? absint( $_GET['user_id'] ) : get_current_user_id();
		if ( 1 > $id || ! current_user_can( 'edit_user', $id ) || ! get_userdata( $id ) ) {
			wp_die( esc_html__( 'This account is unavailable.', 'amazing-security' ), '', array( 'response' => 403 ) );
		}
		echo '<div class="wrap"><h1>Account sessions</h1><p>Review one account at a time. Revocation ends existing WordPress sessions; it cannot be undone and does not revoke application passwords. New logins may create new sessions.</p><form method="get"><input type="hidden" name="page" value="amsec-sessions"><label for="amsec-session-user">User ID</label> <input id="amsec-session-user" type="number" name="user_id" min="1" value="' . esc_attr( (string) $id ) . '"> <button class="button">View account</button></form>';
		try {
			$rows = SessionPolicy::safeRows( \WP_Session_Tokens::get_instance( $id )->get_all() );
		} catch ( \Throwable ) {
			echo '<div class="notice notice-error"><p>Session information is unavailable.</p></div></div>';
			return;
		}
		echo '<table class="widefat striped"><caption>Up to 50 active sessions for user ' . esc_html( (string) $id ) . '</caption><thead><tr><th scope="col">Created UTC</th><th scope="col">Expires UTC</th></tr></thead><tbody>';
		foreach ( $rows as $row ) {
			echo '<tr><td>' . esc_html( gmdate( 'Y-m-d H:i:s', $row['login'] ) ) . '</td><td>' . esc_html( gmdate( 'Y-m-d H:i:s', $row['expiration'] ) ) . '</td></tr>';
		}
		if ( array() === $rows ) {
			echo '<tr><td colspan="2">No sessions returned by the account session manager.</td></tr>';
		}
		echo '</tbody></table><h2>Revoke sessions</h2><p>' . ( get_current_user_id() === $id ? 'Your current session will be kept. Your other sessions will be revoked.' : 'All existing sessions for this selected account will be revoked.' ) . '</p>';
		if ( ! is_ssl() ) {
			echo '<p>Open this page over HTTPS to approve session revocation.</p></div>';
			return;
		}
		echo '<form action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" method="post"><input type="hidden" name="action" value="amsec_sessions_revoke"><input type="hidden" name="user_id" value="' . esc_attr( (string) $id ) . '">';
		wp_nonce_field( 'amsec_sessions_revoke_' . $id );
		echo '<p><label for="amsec-session-password">Your password</label> <input id="amsec-session-password" type="password" name="password" autocomplete="current-password" required maxlength="1024"></p><p><label><input type="checkbox" name="confirm" value="1" required> I understand that revocation cannot be undone.</label></p>';
		submit_button( 'Revoke these sessions', 'secondary' );
		echo '</form></div>';
	}
}
