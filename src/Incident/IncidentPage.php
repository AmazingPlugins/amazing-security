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
		echo '<div class="wrap amazing-security-admin"><h1>If something looks wrong</h1><ol><li>Look at the administrator names below.</li><li>Open that account’s sessions and end the other ones.</li><li>Require a new password for one other account. This signs out its current sessions. It does not email them, and application passwords stay active.</li><li><a href="' . esc_url( admin_url( 'admin.php?page=amazing-security' ) ) . '">Run the scan again.</a></li></ol><p>Change <a href="' . esc_url( admin_url( 'profile.php' ) ) . '">your own password</a> from your profile. If you lock the wrong account out, the host can run <code>wp amazing-security accounts clear-reset</code> with that user id.</p>';
		$policy = new ResetRequirement();
		$users  = get_users(
			array(
				'role'    => 'administrator',
				'number'  => 50,
				'orderby' => 'ID',
				'order'   => 'ASC',
			)
		);
		echo '<table class="widefat striped"><caption>Up to 50 administrator accounts</caption><thead><tr><th>Account</th><th>Reset required</th><th>Sessions</th></tr></thead><tbody>';
		foreach ( $users as $user ) {
			echo '<tr><td>' . esc_html( \AmazingPlugins\Security\Admin\AccountChoice::label( $user->user_login, $user->display_name ) ) . '</td><td>' . ( $policy->required( $user->ID ) ? 'Yes' : 'No' ) . '</td><td><a href="' . esc_url( admin_url( 'admin.php?page=amsec-sessions&user_id=' . $user->ID ) ) . '">Review sessions</a></td></tr>';
		}
		echo '</tbody></table><h2>Require a reset for one other account</h2><p>This cannot be undone. That person must set a new password before password sign-in works again.</p>';
		if ( ! is_ssl() ) {
			echo '<p>Open this page over HTTPS to approve the action.</p></div>';
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only selection; action validates target and nonce.
		$id      = isset( $_GET['user_id'] ) && is_scalar( $_GET['user_id'] ) ? absint( $_GET['user_id'] ) : 0;
		$options = $this->otherAdministrators( $id );
		if ( '' === $options ) {
			echo '<p>You are the only administrator this page can see. Add another administrator before you can require a reset here.</p></div>';
			return;
		}
		echo '<form method="get"><input type="hidden" name="page" value="amsec-incident"><label for="amsec-incident-user">Other administrator</label> <select id="amsec-incident-user" name="user_id" required>';
		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- otherAdministrators() escapes each login and display name.
		echo $options;
		echo '</select> <button class="button">Select account</button></form>';
		$target = get_userdata( $id );
		if ( 0 < $id && get_current_user_id() !== $id && current_user_can( 'edit_user', $id ) && $target instanceof \WP_User ) {
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="amsec_incident_reset"><input type="hidden" name="user_id" value="' . esc_attr( (string) $id ) . '"><p>Selected account: ' . esc_html( \AmazingPlugins\Security\Admin\AccountChoice::label( $target->user_login, $target->display_name ) ) . '</p>';
			wp_nonce_field( 'amsec_incident_reset_' . $id );
			echo '<p><label>Your password <input type="password" name="password" autocomplete="current-password" required maxlength="1024"></label></p><p><label><input type="checkbox" name="confirm" value="1" required> I understand that this account must reset its password and its sessions will be revoked.</label></p>';
			submit_button( __( 'Require password reset', 'amazing-security' ), 'secondary' );
			echo '</form>';
		}
		echo '</div>';
	}

	private function otherAdministrators( int $selected ): string {
		$users = get_users(
			array(
				'role'    => 'administrator',
				'number'  => 50,
				'orderby' => 'display_name',
				'order'   => 'ASC',
			)
		);
		$html  = '';
		foreach ( $users as $user ) {
			if ( ! $user instanceof \WP_User || get_current_user_id() === (int) $user->ID || ! current_user_can( 'edit_user', $user->ID ) ) {
				continue;
			}
			$html .= '<option value="' . esc_attr( (string) $user->ID ) . '"' . selected( $selected, $user->ID, false ) . '>' . esc_html( \AmazingPlugins\Security\Admin\AccountChoice::label( $user->user_login, $user->display_name ) ) . '</option>';
		}
		return $html;
	}
}
