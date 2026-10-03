<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Incident;

final class IncidentPage {
	public function register(): void {
		add_submenu_page( 'amazing-security', __( 'Incident response', 'amazing-security' ), __( 'Incident response', 'amazing-security' ), 'manage_options', 'amsec-incident', array( $this, 'render' ) );
	}

	public function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'amazing-security' ), '', array( 'response' => 403 ) );
		}
		echo '<div class="wrap"><h1>Incident response</h1><p>Review administrators, check findings, and contain a selected account. Requiring a password reset revokes its existing WordPress sessions and blocks password login until a native password reset or password change. Application passwords remain active. No reset email is sent by this action.</p><p>Confirm that WordPress password-reset email works first. For host-level recovery, run <code>wp amazing-security accounts clear-reset &lt;user_id&gt;</code>.</p><p><a class="button" href="' . esc_url( admin_url( 'admin.php?page=amazing-security' ) ) . '">Review security findings</a> <a class="button" href="' . esc_url( admin_url( 'profile.php' ) ) . '">Change your own password</a></p>';
		$policy = new ResetRequirement();
		$users  = get_users(
			array(
				'role'    => 'administrator',
				'number'  => 50,
				'orderby' => 'ID',
				'order'   => 'ASC',
			)
		);
		echo '<table class="widefat striped"><caption>Up to 50 administrator accounts</caption><thead><tr><th>User ID</th><th>Account</th><th>Reset required</th><th>Sessions</th></tr></thead><tbody>';
		foreach ( $users as $user ) {
			echo '<tr><td>' . esc_html( (string) $user->ID ) . '</td><td>' . esc_html( $user->user_login ) . '</td><td>' . ( $policy->required( $user->ID ) ? 'Yes' : 'No' ) . '</td><td><a href="' . esc_url( admin_url( 'admin.php?page=amsec-sessions&user_id=' . $user->ID ) ) . '">Review sessions</a></td></tr>';
		}
		echo '</tbody></table><h2>Require a reset for one other account</h2><p>This action cannot be undone. The selected account must set a new password to sign in again.</p>';
		if ( ! is_ssl() ) {
			echo '<p>Open this page over HTTPS to approve the action.</p></div>';
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only selection; action validates target and nonce.
		$id = isset( $_GET['user_id'] ) && is_scalar( $_GET['user_id'] ) ? absint( $_GET['user_id'] ) : 0;
		echo '<form method="get"><input type="hidden" name="page" value="amsec-incident"><label>User ID <input type="number" name="user_id" min="1" required value="' . esc_attr( (string) $id ) . '"></label> <button class="button">Select account</button></form>';
		if ( 0 < $id && get_current_user_id() !== $id && current_user_can( 'edit_user', $id ) && get_userdata( $id ) ) {
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="amsec_incident_reset"><input type="hidden" name="user_id" value="' . esc_attr( (string) $id ) . '"><p>Selected user ID: ' . esc_html( (string) $id ) . '</p>';
			wp_nonce_field( 'amsec_incident_reset_' . $id );
			echo '<p><label>Your password <input type="password" name="password" autocomplete="current-password" required maxlength="1024"></label></p><p><label><input type="checkbox" name="confirm" value="1" required> I understand that this account must reset its password and its sessions will be revoked.</label></p>';
			submit_button( __( 'Require password reset', 'amazing-security' ), 'secondary' );
			echo '</form>';
		}
		echo '</div>';
	}
}
