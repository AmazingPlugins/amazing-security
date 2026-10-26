<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Traffic;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Free\TrafficGuard\Options;
use AmazingPlugins\Security\Free\TrafficGuard\Page;
use AmazingPlugins\Security\Integrity\WordPressOptions;
use AmazingPlugins\Security\Admin\FixApprovalAction;
use AmazingPlugins\Security\Sessions\SessionPolicy;
use AmazingPlugins\Security\Activity\{ActivityHooks, ActivityRepository};
final class TrafficSettings {
	private function service(): TrafficSettingsService {
		return new TrafficSettingsService( new WordPressOptions() ); }
	public function register(): void {
		$hook = add_submenu_page( 'amazing-security', __( 'PHP traffic history', 'amazing-security-scanner' ), __( 'Traffic history', 'amazing-security-scanner' ), 'manage_options', 'amsec-traffic', array( $this, 'render' ) );
		add_action(
			'admin_enqueue_scripts',
			static function ( string $current ) use ( $hook ): void {
				if ( $current === $hook ) {
					wp_enqueue_style( 'amazing-security-admin', plugins_url( 'assets/admin.css', AMAZING_SECURITY_FILE ), array(), '0.1.0' );
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
			wp_die( esc_html__( 'Secure administrator approval of the current traffic policy is required.', 'amazing-security-scanner' ), '', array( 'response' => 403 ) ); }
		check_admin_referer( 'amsec_traffic_' . $fp );
		$password = is_string( $post['password'] ?? null ) && strlen( $post['password'] ) <= 1024 ? $post['password'] : '';
		$user     = wp_get_current_user();
		if ( '' === $password || ! wp_check_password( $password, $user->user_pass, $user->ID ) ) {
			wp_die( esc_html__( 'Password confirmation failed.', 'amazing-security-scanner' ), '', array( 'response' => 403 ) ); }
		if ( 'saved' !== $service->apply( $fp, '1' === $post['enabled'] ) ) {
			wp_die( esc_html__( 'Traffic policy changed or could not be saved. Review it before approving again.', 'amazing-security-scanner' ), '', array( 'response' => 409 ) ); }
		( new ActivityHooks( new ActivityRepository( $GLOBALS['wpdb'] ) ) )->record( 'security_setting_changed', 0, 'traffic-' . ( '1' === $post['enabled'] ? 'on' : 'off' ) );
		wp_safe_redirect( \AmazingPlugins\Security\Admin\Brand::saved( admin_url( 'admin.php?page=amsec-traffic-guard#history' ) ) );
		exit;
	}
	public function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'amazing-security-scanner' ), '', array( 'response' => 403 ) ); }
		$service = $this->service();
		$state   = $service->status();
		$fp      = $service->fingerprint();
		echo '<div class="wrap amazing-security-admin"><header class="amsec-header"><div><h1>' . esc_html__( 'PHP traffic history', 'amazing-security-scanner' ) . '</h1><p>' . esc_html__( 'A small local history for troubleshooting request behavior.', 'amazing-security-scanner' ) . '</p></div></header><section class="amsec-overview"><h2>' . esc_html__( 'No visitor addresses', 'amazing-security-scanner' ) . '</h2><p>' . esc_html__( 'Off by default. Optional rows contain time, a coarse endpoint category, HTTP method, best-effort response status and fixed security decision. No visitor addresses, URLs, query strings, content, cookies, headers, usernames or user agents are stored. Administrators identified at collection, CLI and cron are skipped.', 'amazing-security-scanner' ) . '</p><details class="amsec-more"><summary>' . esc_html__( 'How it works', 'amazing-security-scanner' ) . '</summary><p>' . esc_html__( 'This is not complete traffic history. Cached/static/CDN responses, terminated processes and dropped records are absent. Collection admits at most 100 rows per minute and 5,000 total rows, without replacing rows during requests. Busy, full or unavailable storage drops records and never changes protection. Records expire from this view after seven days; hourly cleanup deletes up to 500 expired rows. Delayed cron can retain older rows until cleanup.', 'amazing-security-scanner' ) . '</p><p>' .
			/* translators: %1$s and %2$s are inline code snippets (a WP-CLI command or a constant name); keep them unchanged. */
			sprintf( esc_html__( 'A 200 response does not establish a safe request or successful login. Unclassified means no supported decision label was captured. This version labels network and REST-rate blocks only. Disabling stops future collection and retains existing history until expiry. Recovery: %1$s; %2$s bypasses collection.', 'amazing-security-scanner' ), '<code>wp amazing-security traffic disable</code>', '<code>AMSEC_DISABLE_TRAFFIC</code>' ) . '</p></details></section>';
		echo '<section class="amsec-file-scan"><h2>' . esc_html__( 'Collection settings', 'amazing-security-scanner' ) . '</h2>';
		if ( ! empty( $state['invalid'] ) ) {
			echo '<p>' . esc_html__( 'Traffic policy is invalid; collection is unavailable. Use the host recovery command.', 'amazing-security-scanner' ) . '</p>'; } else {
				/* translators: %s: collection state, "on" or "off". */
				echo '<p>' . sprintf( esc_html__( 'Collection: %s.', 'amazing-security-scanner' ), esc_html( $state['enabled'] ? __( 'on', 'amazing-security-scanner' ) : __( 'off', 'amazing-security-scanner' ) ) ) . '</p>';
			if ( is_ssl() ) {
				echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="amsec_traffic_settings"><input type="hidden" name="fingerprint" value="' . esc_attr( $fp ) . '"><p><label>' . esc_html__( 'Collection', 'amazing-security-scanner' ) . ' <select name="enabled"><option value="0"' . selected( $state['enabled'], false, false ) . '>' . esc_html__( 'Off', 'amazing-security-scanner' ) . '</option><option value="1"' . selected( $state['enabled'], true, false ) . '>' . esc_html__( 'On', 'amazing-security-scanner' ) . '</option></select></label></p>';
				wp_nonce_field( 'amsec_traffic_' . $fp );
				echo '<p><label>' . esc_html__( 'Your password', 'amazing-security-scanner' ) . ' <input type="password" name="password" autocomplete="current-password" maxlength="1024" required></label></p><p><label><input type="checkbox" name="confirm" value="1" required> ' . esc_html__( 'I have reviewed the stored fields, retention and incomplete coverage.', 'amazing-security-scanner' ) . '</label></p>';
				submit_button( __( 'Approve traffic collection', 'amazing-security-scanner' ), 'secondary' );
				echo '</form>';
			} else {
				echo '<p>' . esc_html__( 'Use HTTPS to approve collection changes.', 'amazing-security-scanner' ) . '</p>'; }
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
		echo '<section class="amsec-file-scan"><h2>' . esc_html__( 'Recent PHP requests', 'amazing-security-scanner' ) . '</h2><form method="get"><input type="hidden" name="page" value="amsec-traffic"><label>' . esc_html__( 'Endpoint category', 'amazing-security-scanner' ) . ' <select name="category"><option value="">' . esc_html__( 'All categories', 'amazing-security-scanner' ) . '</option>';
		foreach ( TrafficEvent::CATEGORIES as $label ) {
			echo '<option value="' . esc_attr( $label ) . '"' . selected( $category, $label, false ) . '>' . esc_html( $label ) . '</option>'; }
		echo '</select></label> ';
		submit_button( __( 'Filter history', 'amazing-security-scanner' ), 'secondary', '', false );
		echo '</form>';
		try {
			$rows = ( new TrafficRepository( $GLOBALS['wpdb'] ) )->page( $page, $category ); } catch ( \Throwable ) {
					echo '<p>' . esc_html__( 'Traffic storage is unavailable. No complete history can be shown.', 'amazing-security-scanner' ) . '</p></section>';
					return; }
			if ( array() === $rows ) {
				echo '<p>' . esc_html__( 'No retained rows on this page. Empty history does not establish complete collection or safe traffic.', 'amazing-security-scanner' ) . '</p>'; } else {
						echo '<table class="widefat striped"><thead><tr><th scope="col">' . esc_html__( 'Time (UTC)', 'amazing-security-scanner' ) . '</th><th scope="col">' . esc_html__( 'Method', 'amazing-security-scanner' ) . '</th><th scope="col">' . esc_html__( 'Category', 'amazing-security-scanner' ) . '</th><th scope="col">' . esc_html__( 'HTTP status', 'amazing-security-scanner' ) . '</th><th scope="col">' . esc_html__( 'Decision', 'amazing-security-scanner' ) . '</th></tr></thead><tbody>';
				foreach ( $rows as $row ) {
					$timestamp = ctype_digit( (string) ( $row['created_at'] ?? '' ) ) ? (int) $row['created_at'] : 0;
					$status    = ctype_digit( (string) ( $row['status'] ?? '' ) ) ? (int) $row['status'] : 0;
					echo '<tr><td>' . esc_html( $timestamp > 0 ? gmdate( 'Y-m-d H:i:s', $timestamp ) : __( 'Unknown', 'amazing-security-scanner' ) ) . '</td>';
					foreach ( array(
						'method'   => TrafficEvent::METHODS,
						'category' => TrafficEvent::CATEGORIES,
					) as $key => $allowed ) {
						echo '<td>' . esc_html( in_array( $row[ $key ] ?? null, $allowed, true ) ? $row[ $key ] : __( 'Unknown', 'amazing-security-scanner' ) ) . '</td>'; }
					echo '<td>' . esc_html( $status >= 100 && $status <= 599 ? (string) $status : __( 'Unknown', 'amazing-security-scanner' ) ) . '</td><td>' . esc_html( in_array( $row['decision'] ?? null, TrafficEvent::DECISIONS, true ) ? $row['decision'] : __( 'Unknown', 'amazing-security-scanner' ) ) . '</td></tr>';
				}
				echo '</tbody></table>';
				}
				$link   = static fn( int $target, string $label ): string => '<a class="amsec-pager-nav" href="' . esc_url(
					add_query_arg(
						array(
							'page'         => 'amsec-traffic',
							'traffic_page' => $target,
							'category'     => $category,
						),
						admin_url( 'admin.php' )
					)
				) . '">' . esc_html( $label ) . '</a>';
				$spacer = static fn( string $label ): string => '<span class="amsec-pager-nav is-spacer" aria-hidden="true">' . esc_html( $label ) . '</span>';
				echo '<nav class="amsec-pager" aria-label="' . esc_attr__( 'History pages', 'amazing-security-scanner' ) . '">';
				echo wp_kses( $page > 1 ? $link( $page - 1, __( 'Previous', 'amazing-security-scanner' ) ) : $spacer( __( 'Previous', 'amazing-security-scanner' ) ), \AmazingPlugins\Security\Admin\AdminHtml::allowed() );
				/* translators: %s: current page number in the traffic history list. */
				echo '<span class="amsec-pager-label">' . sprintf( esc_html__( 'Page %s', 'amazing-security-scanner' ), esc_html( (string) $page ) ) . '</span>';
				// A full page of 50 rows may have more after it; the list stops at page 100.
				echo wp_kses( count( $rows ) >= 50 && $page < 100 ? $link( $page + 1, __( 'Next', 'amazing-security-scanner' ) ) : $spacer( __( 'Next', 'amazing-security-scanner' ) ), \AmazingPlugins\Security\Admin\AdminHtml::allowed() );
				echo '</nav></section>';
	}
	public function recovery( array $args, array $assoc ): void {
		if ( array() !== $args || array() !== $assoc ) {
			\WP_CLI::error( 'This command accepts no arguments.' ); }
		if ( ! $this->service()->disable() ) {
			\WP_CLI::error( 'Traffic collection could not be disabled.' ); }
		// The Traffic screen's blocking controls: block lists, live log, hotlink, precise blocks and comment checks.
		foreach ( array( Options::HOSTNAMES, Options::AGENTS, Options::REFERRERS ) as $list ) {
			update_option( $list, '' );
		}
		foreach ( array( Options::LIVE, Options::HOTLINK, 'amsec_precise_block', 'amsec_comment_honeypot', 'amsec_comment_rate', 'amsec_comment_spam_hold' ) as $flag ) {
			update_option( $flag, '0' );
		}
		( new Page() )->syncHotlink( '0' );
		( new ActivityHooks( new ActivityRepository( $GLOBALS['wpdb'] ) ) )->record( 'security_setting_changed', 0, 'traffic-off' );
		\WP_CLI::success( 'Traffic history, block lists, live log, hotlink protection, precise blocks and comment checks are off. Retained history expires separately.' );
	}
}
