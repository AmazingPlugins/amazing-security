<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Incident;

defined( 'ABSPATH' ) || exit;

final class IncidentPage {
	public function register(): void {
		add_submenu_page( 'amsec-security-scanner', __( 'Incident response', 'amsec-security-scanner' ), __( 'Incident response', 'amsec-security-scanner' ), 'manage_options', 'amsec-incident', array( $this, 'render' ) );
	}

	public function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'amsec-security-scanner' ), '', array( 'response' => 403 ) );
		}
		echo '<div class="wrap amsec-security-scanner-admin"><h1>' . esc_html__( 'If something looks wrong', 'amsec-security-scanner' ) . '</h1><ol><li>' . esc_html__( 'Look at the administrator names below.', 'amsec-security-scanner' ) . '</li><li>' . esc_html__( 'Open that account’s sessions and end the other ones.', 'amsec-security-scanner' ) . '</li><li>' . esc_html__( 'Require a new password for one other account. This signs out its current sessions. It does not email them, and application passwords stay active.', 'amsec-security-scanner' ) . '</li><li><a href="' . esc_url( admin_url( 'admin.php?page=amsec-security-scanner' ) ) . '">' . esc_html__( 'Run the scan again.', 'amsec-security-scanner' ) . '</a></li></ol><p>' . esc_html__( 'Change', 'amsec-security-scanner' ) . ' <a href="' . esc_url( admin_url( 'profile.php' ) ) . '">' . esc_html__( 'your own password', 'amsec-security-scanner' ) . '</a> ' . esc_html__( 'from your profile. If you lock the wrong account out, the host can run', 'amsec-security-scanner' ) . ' <code>wp amsec-security-scanner accounts clear-reset</code> ' . esc_html__( 'with that user id.', 'amsec-security-scanner' ) . '</p>';
		$policy = new ResetRequirement();
		$users  = get_users(
			array(
				'role'    => 'administrator',
				'number'  => 50,
				'orderby' => 'ID',
				'order'   => 'ASC',
			)
		);
		echo '<table class="widefat striped"><caption>' . esc_html__( 'Up to 50 administrator accounts', 'amsec-security-scanner' ) . '</caption><thead><tr><th>' . esc_html__( 'Account', 'amsec-security-scanner' ) . '</th><th>' . esc_html__( 'Reset required', 'amsec-security-scanner' ) . '</th><th>' . esc_html__( 'Sessions', 'amsec-security-scanner' ) . '</th></tr></thead><tbody>';
		foreach ( $users as $user ) {
			echo '<tr><td>' . esc_html( \AmazingPlugins\Security\Admin\AccountChoice::label( $user->user_login, $user->display_name ) ) . '</td><td>' . ( $policy->required( $user->ID ) ? esc_html__( 'Yes', 'amsec-security-scanner' ) : esc_html__( 'No', 'amsec-security-scanner' ) ) . '</td><td><a href="' . esc_url( admin_url( 'admin.php?page=amsec-sessions&user_id=' . $user->ID ) ) . '">' . esc_html__( 'Review sessions', 'amsec-security-scanner' ) . '</a></td></tr>';
		}
		echo '</tbody></table><h2>' . esc_html__( 'Require a reset for one other account', 'amsec-security-scanner' ) . '</h2><p>' . esc_html__( 'This cannot be undone. That person must set a new password before password sign-in works again.', 'amsec-security-scanner' ) . '</p>';
		if ( ! is_ssl() ) {
			echo '<p>' . esc_html__( 'Open this page over HTTPS to approve the action.', 'amsec-security-scanner' ) . '</p></div>';
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only selection; action validates target and nonce.
		$id      = isset( $_GET['user_id'] ) && is_scalar( $_GET['user_id'] ) ? absint( $_GET['user_id'] ) : 0;
		$options = $this->otherAdministrators( $id );
		if ( '' === $options ) {
			echo '<p>' . esc_html__( 'You are the only administrator this page can see. Add another administrator before you can require a reset here.', 'amsec-security-scanner' ) . '</p></div>';
			return;
		}
		echo '<form method="get"><input type="hidden" name="page" value="amsec-incident"><label for="amsec-incident-user">' . esc_html__( 'Other administrator', 'amsec-security-scanner' ) . '</label> <select id="amsec-incident-user" name="user_id" required>';
		echo wp_kses( $options, \AmazingPlugins\Security\Admin\AdminHtml::allowed() );
		echo '</select> <button class="button">' . esc_html__( 'Select account', 'amsec-security-scanner' ) . '</button></form>';
		$target = get_userdata( $id );
		if ( 0 < $id && get_current_user_id() !== $id && current_user_can( 'edit_user', $id ) && $target instanceof \WP_User ) {
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="amsec_incident_reset"><input type="hidden" name="user_id" value="' . esc_attr( (string) $id ) . '"><p>' . esc_html__( 'Selected account:', 'amsec-security-scanner' ) . ' ' . esc_html( \AmazingPlugins\Security\Admin\AccountChoice::label( $target->user_login, $target->display_name ) ) . '</p>';
			wp_nonce_field( 'amsec_incident_reset_' . $id );
			echo '<p><label>' . esc_html__( 'Your password', 'amsec-security-scanner' ) . ' <input type="password" name="password" autocomplete="current-password" required maxlength="1024"></label></p><p><label><input type="checkbox" name="confirm" value="1" required> ' . esc_html__( 'I understand that this account must reset its password and its sessions will be revoked.', 'amsec-security-scanner' ) . '</label></p>';
			submit_button( __( 'Require password reset', 'amsec-security-scanner' ), 'secondary' );
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
