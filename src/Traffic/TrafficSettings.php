<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Traffic;

use AmazingPlugins\Security\Integrity\WordPressOptions;
use AmazingPlugins\Security\Admin\FixApprovalAction;
use AmazingPlugins\Security\Sessions\SessionPolicy;
use AmazingPlugins\Security\Activity\{ActivityHooks, ActivityRepository};
final class TrafficSettings {
	private function service(): TrafficSettingsService {
		return new TrafficSettingsService( new WordPressOptions() ); }
	public function register(): void {
		$hook = add_submenu_page( 'amazing-security', __( 'PHP traffic history', 'amazing-security' ), __( 'Traffic history', 'amazing-security' ), 'manage_options', 'amsec-traffic', array( $this, 'render' ) );
		add_action(
			'admin_enqueue_scripts',
			static function ( string $current ) use ( $hook ): void {
				if ( $current === $hook ) {
					wp_enqueue_style( 'amazing-security-admin', plugins_url( 'assets/admin.css', AMAZING_SECURITY_FILE ), array(), AMAZING_SECURITY_VERSION );
				} }
		);
	}
	public function handle(): void {
	 // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Exact-policy nonce checked before any mutation.
		$post    = wp_unslash( $_POST );
		$method  = is_string( $_SERVER['REQUEST_METHOD'] ?? null ) ? sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '';
		$auth    = wp_parse_auth_cookie( '', is_ssl() ? 'secure_auth' : 'auth' );
		$service = $this->service();
		$state   = $service->status();
		$fp      = $service->fingerprint();
		if ( ! SessionPolicy::allowed( 'post' === $method, current_user_can( 'manage_options' ), empty( $state['invalid'] ) && in_array( $post['enabled'] ?? null, array( '0', '1' ), true ) && is_string( $post['fingerprint'] ?? null ) && $post['fingerprint'] === $fp, FixApprovalAction::cookieAuthenticated() && SessionPolicy::matchingTokens( is_array( $auth ) ? (string) $auth['token'] : '', wp_get_session_token() ), is_ssl(), '1' === ( $post['confirm'] ?? null ) ) ) {
			wp_die( esc_html__( 'Secure administrator approval of the current traffic policy is required.', 'amazing-security' ), '', array( 'response' => 403 ) ); }
		check_admin_referer( 'amsec_traffic_' . $fp );
		$password = is_string( $post['password'] ?? null ) && strlen( $post['password'] ) <= 1024 ? $post['password'] : '';
		$user     = wp_get_current_user();
		if ( '' === $password || ! wp_check_password( $password, $user->user_pass, $user->ID ) ) {
			wp_die( esc_html__( 'Password confirmation failed.', 'amazing-security' ), '', array( 'response' => 403 ) ); }
		if ( 'saved' !== $service->apply( $fp, '1' === $post['enabled'] ) ) {
			wp_die( esc_html__( 'Traffic policy changed or could not be saved. Review it before approving again.', 'amazing-security' ), '', array( 'response' => 409 ) ); }
		( new ActivityHooks( new ActivityRepository( $GLOBALS['wpdb'] ) ) )->record( 'security_setting_changed', 0, 'traffic-' . ( '1' === $post['enabled'] ? 'on' : 'off' ) );
		wp_safe_redirect( admin_url( 'admin.php?page=amsec-traffic' ) );
		exit;
	}
	public function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'amazing-security' ), '', array( 'response' => 403 ) ); }
		$service = $this->service();
		$state   = $service->status();
		$fp      = $service->fingerprint();
		echo '<div class="wrap amazing-security-admin"><header class="amsec-header"><div><h1>PHP traffic history</h1><p>A small local history for troubleshooting request behavior.</p></div></header><section class="amsec-overview"><h2>No visitor addresses</h2><p>Off by default. Optional rows contain time, a coarse endpoint category, HTTP method, best-effort response status and fixed security decision. No visitor addresses, URLs, query strings, content, cookies, headers, usernames or user agents are stored. Administrators identified at collection, CLI and cron are skipped.</p><p>This is not complete traffic history. Cached/static/CDN responses, terminated processes and dropped records are absent. Collection admits at most 100 rows per minute and 5,000 total rows, without replacing rows during requests. Busy, full or unavailable storage drops records and never changes protection. Records expire from this view after seven days; hourly cleanup deletes up to 500 expired rows. Delayed cron can retain older rows until cleanup.</p><p>A 200 response does not establish a safe request or successful login. Unclassified means no supported decision label was captured. This version labels network and REST-rate blocks only. Disabling stops future collection and retains existing history until expiry. Recovery: <code>wp amazing-security traffic disable</code>; <code>AMSEC_DISABLE_TRAFFIC</code> bypasses collection.</p></section>';
		echo '<section class="amsec-file-scan"><h2>Collection settings</h2>';
		if ( ! empty( $state['invalid'] ) ) {
			echo '<p>Traffic policy is invalid; collection is unavailable. Use the host recovery command.</p>'; } else {
				echo '<p>Collection: ' . esc_html( $state['enabled'] ? 'on' : 'off' ) . '.</p>';
			if ( is_ssl() ) {
				echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="amsec_traffic_settings"><input type="hidden" name="fingerprint" value="' . esc_attr( $fp ) . '"><p><label>Collection <select name="enabled"><option value="0"' . selected( $state['enabled'], false, false ) . '>Off</option><option value="1"' . selected( $state['enabled'], true, false ) . '>On</option></select></label></p>';
				wp_nonce_field( 'amsec_traffic_' . $fp );
				echo '<p><label>Your password <input type="password" name="password" autocomplete="current-password" maxlength="1024" required></label></p><p><label><input type="checkbox" name="confirm" value="1" required> I have reviewed the stored fields, retention and incomplete coverage.</label></p>';
				submit_button( __( 'Approve traffic collection', 'amazing-security' ), 'secondary' );
				echo '</form>';
			} else {
				echo '<p>Use HTTPS to approve collection changes.</p>'; }
			}
			echo '</section>';
			$this->history();
			echo '</div>';
	}
	private function history(): void {
	 // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only bounded administrator pagination.
		$page = max( 1, min( 100, absint( $_GET['traffic_page'] ?? 1 ) ) );
	 // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only fixed category filter.
		$category = is_string( $_GET['category'] ?? null ) ? sanitize_key( wp_unslash( $_GET['category'] ) ) : '';
		if ( ! in_array( $category, TrafficEvent::CATEGORIES, true ) ) {
			$category = ''; }
		echo '<section class="amsec-file-scan"><h2>Recent PHP requests</h2><form method="get"><input type="hidden" name="page" value="amsec-traffic"><label>Endpoint category <select name="category"><option value="">All categories</option>';
		foreach ( TrafficEvent::CATEGORIES as $label ) {
			echo '<option value="' . esc_attr( $label ) . '"' . selected( $category, $label, false ) . '>' . esc_html( $label ) . '</option>'; }
		echo '</select></label> ';
		submit_button( __( 'Filter history', 'amazing-security' ), 'secondary', '', false );
		echo '</form>';
		try {
			$rows = ( new TrafficRepository( $GLOBALS['wpdb'] ) )->page( $page, $category ); } catch ( \Throwable ) {
					echo '<p>Traffic storage is unavailable. No complete history can be shown.</p></section>';
					return; }
			if ( array() === $rows ) {
				echo '<p>No retained rows on this page. Empty history does not establish complete collection or safe traffic.</p>'; } else {
						echo '<table class="widefat striped"><thead><tr><th scope="col">Time (UTC)</th><th scope="col">Method</th><th scope="col">Category</th><th scope="col">HTTP status</th><th scope="col">Decision</th></tr></thead><tbody>';
				foreach ( $rows as $row ) {
					$timestamp = ctype_digit( (string) ( $row['created_at'] ?? '' ) ) ? (int) $row['created_at'] : 0;
					$status    = ctype_digit( (string) ( $row['status'] ?? '' ) ) ? (int) $row['status'] : 0;
					echo '<tr><td>' . esc_html( $timestamp > 0 ? gmdate( 'Y-m-d H:i:s', $timestamp ) : 'Unknown' ) . '</td>';
					foreach ( array(
						'method'   => TrafficEvent::METHODS,
						'category' => TrafficEvent::CATEGORIES,
					) as $key => $allowed ) {
						echo '<td>' . esc_html( in_array( $row[ $key ] ?? null, $allowed, true ) ? $row[ $key ] : 'Unknown' ) . '</td>'; }
					echo '<td>' . esc_html( $status >= 100 && $status <= 599 ? (string) $status : 'Unknown' ) . '</td><td>' . esc_html( in_array( $row['decision'] ?? null, TrafficEvent::DECISIONS, true ) ? $row['decision'] : 'Unknown' ) . '</td></tr>';
				}
				echo '</tbody></table>';
				}
				echo '<p>Page ' . esc_html( (string) $page ) . ' · Up to 50 rows per page</p><p>';
				foreach ( array(
					'Previous' => max( 1, $page - 1 ),
					'Next'     => min( 100, $page + 1 ),
				) as $label => $target ) {
					echo '<a class="button" href="' . esc_url(
						add_query_arg(
							array(
								'page'         => 'amsec-traffic',
								'traffic_page' => $target,
								'category'     => $category,
							),
							admin_url( 'admin.php' )
						)
					) . '">' . esc_html( $label ) . '</a> '; }
				echo '</p></section>';
	}
	public function recovery( array $args, array $assoc ): void {
		if ( array() !== $args || array() !== $assoc ) {
			\WP_CLI::error( 'This command accepts no arguments.' ); }
		if ( ! $this->service()->disable() ) {
			\WP_CLI::error( 'Traffic collection could not be disabled.' ); }
		( new ActivityHooks( new ActivityRepository( $GLOBALS['wpdb'] ) ) )->record( 'security_setting_changed', 0, 'traffic-off' );
		\WP_CLI::success( 'Traffic collection is off; retained history expires separately.' );
	}
}
