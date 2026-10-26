<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Bots;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Activity\ActivityHooks;
use AmazingPlugins\Security\Activity\ActivityRepository;
use AmazingPlugins\Security\Proxy\WordPressClientAddress;

/** Counts guest requests that hunt for weak spots, and can pause an address that sends too many. */
final class ScannerGuard {
	public const OPTION = 'amsec_scanner_mode';
	private const MODES = array( 'off', 'watch', 'block' );

	public static function mode(): string {
		$value = get_option( self::OPTION, 'off' );
		return in_array( $value, self::MODES, true ) ? $value : 'off';
	}

	public function check(): void {
		$mode = self::mode();
		if ( 'off' === $mode || is_user_logged_in() || is_admin() || wp_doing_cron() || wp_doing_ajax() || ( defined( 'WP_CLI' ) && WP_CLI ) || ( defined( 'AMSEC_DISABLE_FIREWALL' ) && AMSEC_DISABLE_FIREWALL ) ) {
			return;
		}
		$client = new WordPressClientAddress();
		// The never-limit list and the site's own requests are shared with the rate limiter, because the block key is shared too.
		if ( RateLimiter::exempt( $client, RateLimiter::settings()['allow'] ) ) {
			return;
		}
		$key   = $client->key( wp_salt( 'auth' ) . ':bot:scanner', true )->fromServer( $_SERVER );
		$block = $client->key( wp_salt( 'auth' ) . RateLimiter::BLOCK_SALT, true )->fromServer( $_SERVER );
		if ( null === $key || null === $block ) {
			return;
		}
		$store = new BotCounterStore( $GLOBALS['wpdb'] );
		$now   = time();
		if ( 'block' === $mode && $store->blocked( $block, $now ) ) {
			self::deny();
		}
		$agent = is_string( $_SERVER['HTTP_USER_AGENT'] ?? null ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Only compared against fixed patterns; never stored or printed.
		$uri  = is_string( $_SERVER['REQUEST_URI'] ?? null ) ? wp_unslash( $_SERVER['REQUEST_URI'] ) : '';
		$path = (string) wp_parse_url( $uri, PHP_URL_PATH );
		$hit  = ProbePolicy::agent( $agent ) || ( is_404() && ProbePolicy::path( $path, static fn( string $slug ): bool => is_dir( WP_PLUGIN_DIR . '/' . $slug ) ) );
		if ( ! $hit ) {
			return;
		}
		$decision = ProbePolicy::decide( $mode, $store->record( $key, ProbePolicy::WINDOW, $now ) );
		if ( 'none' === $decision ) {
			return;
		}
		if ( $store->flag( $key, $now, ProbePolicy::WINDOW ) ) {
			( new ActivityHooks( new ActivityRepository( $GLOBALS['wpdb'] ) ) )->record( 'block' === $decision ? 'scanner_blocked' : 'scanner_flagged' );
		}
		if ( 'block' === $decision ) {
			$store->block( $block, $now + ProbePolicy::BLOCK, $now );
			self::deny();
		}
	}

	private static function deny(): void {
		status_header( 403 );
		nocache_headers();
		header( 'Content-Type: text/plain; charset=utf-8' );
		echo esc_html__( 'Access is paused for your address because it sent too many suspicious requests. Please try again in an hour.', 'amazing-security' );
		exit;
	}

	public function handle(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'amazing-security' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'amsec_scanner_guard' );
		$mode = is_string( $_POST['mode'] ?? null ) ? sanitize_key( wp_unslash( $_POST['mode'] ) ) : '';
		if ( ! in_array( $mode, self::MODES, true ) ) {
			wp_die( esc_html__( 'Choose Off, Watch or Block.', 'amazing-security' ), '', array( 'response' => 400 ) );
		}
		if ( 'block' === $mode && RateLimiter::proxyUnresolved() ) {
			wp_safe_redirect( add_query_arg( 'amsec_scanner_error', 'proxy', admin_url( 'admin.php?page=amsec-traffic-guard' ) ) . '#bots' );
			exit;
		}
		update_option( self::OPTION, $mode, false );
		( new ActivityHooks( new ActivityRepository( $GLOBALS['wpdb'] ) ) )->record( 'security_setting_changed', 0, 'scanner-guard-' . $mode );
		wp_safe_redirect( \AmazingPlugins\Security\Admin\Brand::saved( admin_url( 'admin.php?page=amsec-traffic-guard#bots' ) ) );
		exit;
	}

	public function render(): void {
		$mode    = self::mode();
		$choices = array(
			'off'   => __( 'Off', 'amazing-security' ),
			'watch' => __( 'Watch', 'amazing-security' ),
			'block' => __( 'Block', 'amazing-security' ),
		);
		$count   = ( new BotCounterStore( $GLOBALS['wpdb'] ) )->flaggedSince( time() - DAY_IN_SECONDS );
		echo '<div class="wrap amazing-security-admin amsec-brief">';
		echo '<h2>' . esc_html__( 'Scanner guard', 'amazing-security' ) . '</h2>';
		$flash = isset( $_GET['amsec_scanner_error'] ) ? sanitize_key( wp_unslash( $_GET['amsec_scanner_error'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only flash after saving.
		if ( 'proxy' === $flash ) {
			echo '<div class="notice notice-error inline"><p>' . esc_html__( 'Block is off because requests arrive through a proxy this site does not trust yet. Every visitor would share one address. Add the proxy under Trusted proxies first, or choose Watch.', 'amazing-security' ) . '</p></div>';
		}
		echo '<p class="amsec-brief-status"><span class="amsec-pill' . ( 'off' === $mode ? ' is-off' : ' is-on' ) . '">' . esc_html( $choices[ $mode ] ) . '</span>';
		echo esc_html__( 'Catches tools that hunt for weak spots on your site.', 'amazing-security' ) . '</p>';
		echo '<ul class="amsec-facts"><li><strong>' . esc_html( null === $count ? '-' : number_format_i18n( $count ) ) . '</strong> ';
		$n = (int) $count;
		echo esc_html( 'block' === $mode ? _n( 'address blocked or flagged in the last 24 hours', 'addresses blocked or flagged in the last 24 hours', $n, 'amazing-security' ) : _n( 'address flagged in the last 24 hours', 'addresses flagged in the last 24 hours', $n, 'amazing-security' ) ) . '</li></ul>';
		echo '<details class="amsec-more"><summary>' . esc_html__( 'How it works', 'amazing-security' ) . '</summary>';
		echo '<p>' . esc_html__( 'Some visitors ask for files a normal site never links to, like .env, .git, old wp-config copies, phpinfo.php, or known backdoor names. Others announce a scanning tool such as sqlmap or wpscan. Each of these counts as one hit.', 'amazing-security' ) . '</p>';
		echo '<p>' . esc_html__( 'Five hits in ten minutes from one address sets it off. Watch writes one line to the activity log. Block also shows that address an error page for one hour.', 'amazing-security' ) . '</p>';
		echo '<p>' . esc_html__( 'Signed-in people are never counted or blocked. The site stores a salted key for the address, not the address itself.', 'amazing-security' ) . '</p></details>';
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="amsec_scanner_guard">';
		wp_nonce_field( 'amsec_scanner_guard' );
		echo '<p><label for="amsec-scanner-mode">' . esc_html__( 'Scanner guard', 'amazing-security' ) . '</label> <select id="amsec-scanner-mode" name="mode">';
		foreach ( $choices as $value => $choice ) {
			echo '<option value="' . esc_attr( $value ) . '"' . selected( $mode, $value, false ) . '>' . esc_html( $choice ) . '</option>';
		}
		echo '</select> ';
		submit_button( __( 'Save scanner guard', 'amazing-security' ), 'secondary', 'amsec-scanner-save', false );
		echo '</p></form></div>';
	}
}
