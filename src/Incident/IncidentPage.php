<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Incident;

defined( 'ABSPATH' ) || exit;

final class IncidentPage {
	public function register(): void {
		add_submenu_page( 'amazing-security', __( 'Incident response', 'amazing-security' ), __( 'Incident response', 'amazing-security' ), 'manage_options', 'amsec-incident', array( $this, 'render' ) );
	}

	public function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'amazing-security' ), '', array( 'response' => 403 ) );
		}
		echo '<div class="wrap amazing-security-admin"><h1>' . esc_html__( 'If something looks wrong', 'amazing-security' ) . '</h1><ol><li>' . esc_html__( 'Look at the administrator names below.', 'amazing-security' ) . '</li><li>' . esc_html__( 'Open that account’s sessions and end the other ones.', 'amazing-security' ) . '</li><li>' . esc_html__( 'Require a new password for one other account. This signs out its current sessions. It does not email them, and application passwords stay active.', 'amazing-security' ) . '</li><li><a href="' . esc_url( admin_url( 'admin.php?page=amazing-security' ) ) . '">' . esc_html__( 'Run the scan again.', 'amazing-security' ) . '</a></li></ol><p>' . esc_html__( 'Change', 'amazing-security' ) . ' <a href="' . esc_url( admin_url( 'profile.php' ) ) . '">' . esc_html__( 'your own password', 'amazing-security' ) . '</a> ' . esc_html__( 'from your profile. If you lock the wrong account out, the host can run', 'amazing-security' ) . ' <code>wp amazing-security accounts clear-reset</code> ' . esc_html__( 'with that user id.', 'amazing-security' ) . '</p>';
		$policy = new ResetRequirement();
		$users  = get_users(
			array(
				'role'    => 'administrator',
				'number'  => 50,
				'orderby' => 'ID',
				'order'   => 'ASC',
			)
		);
		echo '<table class="widefat striped"><caption>' . esc_html__( 'Up to 50 administrator accounts', 'amazing-security' ) . '</caption><thead><tr><th>' . esc_html__( 'Account', 'amazing-security' ) . '</th><th>' . esc_html__( 'Reset required', 'amazing-security' ) . '</th><th>' . esc_html__( 'Sessions', 'amazing-security' ) . '</th></tr></thead><tbody>';
		foreach ( $users as $user ) {
			echo '<tr><td>' . esc_html( \AmazingPlugins\Security\Admin\AccountChoice::label( $user->user_login, $user->display_name ) ) . '</td><td>' . ( $policy->required( $user->ID ) ? esc_html__( 'Yes', 'amazing-security' ) : esc_html__( 'No', 'amazing-security' ) ) . '</td><td><a href="' . esc_url( admin_url( 'admin.php?page=amsec-sessions&user_id=' . $user->ID ) ) . '">' . esc_html__( 'Review sessions', 'amazing-security' ) . '</a></td></tr>';
		}
		echo '</tbody></table><h2>' . esc_html__( 'Require a reset for one other account', 'amazing-security' ) . '</h2><p>' . esc_html__( 'This cannot be undone. That person must set a new password before password sign-in works again.', 'amazing-security' ) . '</p>';
		if ( ! is_ssl() ) {
			echo '<p>' . esc_html__( 'Open this page over HTTPS to approve the action.', 'amazing-security' ) . '</p></div>';
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only selection; action validates target and nonce.
		$id      = isset( $_GET['user_id'] ) && is_scalar( $_GET['user_id'] ) ? absint( $_GET['user_id'] ) : 0;
		$options = $this->otherAdministrators( $id );
		if ( '' === $options ) {
			echo '<p>' . esc_html__( 'You are the only administrator this page can see. Add another administrator before you can require a reset here.', 'amazing-security' ) . '</p></div>';
			return;
		}
		echo '<form method="get"><input type="hidden" name="page" value="amsec-incident"><label for="amsec-incident-user">' . esc_html__( 'Other administrator', 'amazing-security' ) . '</label> <select id="amsec-incident-user" name="user_id" required>';
		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- otherAdministrators() escapes each login and display name.
		echo $options;
		echo '</select> <button class="button">' . esc_html__( 'Select account', 'amazing-security' ) . '</button></form>';
		$target = get_userdata( $id );
		if ( 0 < $id && get_current_user_id() !== $id && current_user_can( 'edit_user', $id ) && $target instanceof \WP_User ) {
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="amsec_incident_reset"><input type="hidden" name="user_id" value="' . esc_attr( (string) $id ) . '"><p>' . esc_html__( 'Selected account:', 'amazing-security' ) . ' ' . esc_html( \AmazingPlugins\Security\Admin\AccountChoice::label( $target->user_login, $target->display_name ) ) . '</p>';
			wp_nonce_field( 'amsec_incident_reset_' . $id );
			echo '<p><label>' . esc_html__( 'Your password', 'amazing-security' ) . ' <input type="password" name="password" autocomplete="current-password" required maxlength="1024"></label></p><p><label><input type="checkbox" name="confirm" value="1" required> ' . esc_html__( 'I understand that this account must reset its password and its sessions will be revoked.', 'amazing-security' ) . '</label></p>';
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
