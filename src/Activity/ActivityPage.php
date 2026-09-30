<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Activity;

final class ActivityPage {
	public function register(): void {
		add_submenu_page( 'amazing-security', 'Security activity', 'Activity', 'manage_options', 'amsec-activity', array( $this, 'render' ) );
	}

	public function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You cannot view security activity.', 'amazing-security' ), '', array( 'response' => 403 ) );
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only administrator filter; no mutation.
		$page = max( 1, min( 200, absint( $_GET['activity_page'] ?? 1 ) ) );
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only allowlisted filter.
		$event = isset( $_GET['event'] ) && is_string( $_GET['event'] ) ? sanitize_key( wp_unslash( $_GET['event'] ) ) : '';
		if ( ! in_array( $event, ActivityEvent::TYPES, true ) ) {
			$event = '';
		}
		try {
			$rows = ( new ActivityRepository( $GLOBALS['wpdb'] ) )->page( $page, $event );
			// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Renderer escapes every dynamic field.
			echo ( new ActivityRenderer() )->render( $rows, $page, $event );
		} catch ( \RuntimeException ) {
			echo '<div class="wrap"><h1>Security activity</h1><div class="notice notice-error"><p>Activity storage is unavailable. No complete history can be shown.</p></div></div>';
		}
	}
}
