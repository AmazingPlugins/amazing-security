<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Activity;

final class ActivityPage {
	public function register(): void {
		add_submenu_page( 'amazing-security', __( 'Security activity', 'amazing-security' ), __( 'Activity', 'amazing-security' ), 'manage_options', 'amsec-activity', array( $this, 'render' ) );
	}

	public function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You cannot view security activity.', 'amazing-security' ), '', array( 'response' => 403 ) );
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only administrator filter; no mutation.
		$page = ActivityRepository::pageNumber( absint( $_GET['activity_page'] ?? 1 ) );
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only allowlisted filter.
		$event = isset( $_GET['event'] ) && is_string( $_GET['event'] ) ? sanitize_key( wp_unslash( $_GET['event'] ) ) : '';
		if ( ! in_array( $event, ActivityEvent::TYPES, true ) ) {
			$event = '';
		}
		try {
			$records = new ActivityRepository( $GLOBALS['wpdb'] );
			$rows    = $records->page( $page, $event );
			$pages   = ActivityRepository::pageCount( $records->count( $event ) );
			$enabled = '1' === get_option( 'amsec_activity_enabled', '0' );
			// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Renderer escapes every dynamic field.
			echo ( new ActivityRenderer() )->render( $rows, $page, $event, $pages, $this->switchForm( $enabled ) );
		} catch ( \RuntimeException ) {
			echo '<div class="wrap amazing-security-admin"><h1>Security activity</h1><div class="notice notice-error"><p>Activity storage is unavailable. No complete history can be shown.</p></div></div>';
		}
	}

	public function save(): void {
		$method = isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '';
		if ( 'post' !== $method || ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'amazing-security' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'amsec_activity_recording' );
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce checked above.
		$raw = isset( $_POST['amsec_activity_enabled'] ) ? sanitize_text_field( wp_unslash( $_POST['amsec_activity_enabled'] ) ) : '0';
		update_option( 'amsec_activity_enabled', '1' === $raw ? '1' : '0', false );
		wp_safe_redirect( admin_url( 'admin.php?page=amsec-activity' ) );
		exit;
	}

	private function switchForm( bool $enabled ): string {
		$status = $enabled
			? __( 'Recording is on. New sign-ins, account changes, and plugin or theme changes are stored.', 'amazing-security' )
			: __( 'Recording is off. Turn it on before new sign-ins, account changes, and plugin or theme changes are stored.', 'amazing-security' );
		$html   = '<form class="amsec-activity-switch" method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
		$html  .= '<input type="hidden" name="action" value="amsec_activity_recording">';
		$html  .= '<p>' . esc_html( $status ) . '</p>';
		$html  .= wp_nonce_field( 'amsec_activity_recording', '_wpnonce', true, false );
		$html  .= '<p><label><input type="checkbox" name="amsec_activity_enabled" value="1"' . checked( $enabled, true, false ) . '> ';
		$html  .= esc_html__( 'Record security activity', 'amazing-security' ) . '</label></p>';
		$html  .= get_submit_button( __( 'Save activity recording', 'amazing-security' ), 'secondary', 'submit', false );
		return $html . '</form>';
	}
}
