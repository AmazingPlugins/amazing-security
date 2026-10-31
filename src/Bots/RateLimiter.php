<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Bots;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Activity\ActivityHooks;
use AmazingPlugins\Security\Activity\ActivityRepository;
use AmazingPlugins\Security\Network\Cidr;
use AmazingPlugins\Security\Proxy\WordPressClientAddress;

/** Counts guest requests per minute and can pause an address that sends too many. */
final class RateLimiter {
	public const OPTION = 'amsec_rate_limits';
	public const RECENT = 'amsec_rate_limit_recent';
	/** Block key shared with the scanner guard, so both features give one answer for an address. */
	public const BLOCK_SALT = ':bot:block';
	private const WINDOW    = 60;
	private bool $counted   = false;

	public static function settings(): array {
		return RatePolicy::read( get_option( self::OPTION, null ) );
	}

	/** Runs at init priority 0. REST requests wait for REST authentication so application passwords count as signed in. */
	public function check(): void {
		$stored = get_option( self::OPTION, null );
		if ( ! is_array( $stored ) || ! in_array( $stored['mode'] ?? null, array( 'watch', 'block' ), true ) ) {
			return;
		}
		if ( is_user_logged_in() || wp_doing_cron() || ( defined( 'WP_CLI' ) && WP_CLI ) || ( defined( 'AMSEC_DISABLE_FIREWALL' ) && AMSEC_DISABLE_FIREWALL ) ) {
			return;
		}
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Only the path is compared against a fixed prefix.
		$uri  = is_string( $_SERVER['REQUEST_URI'] ?? null ) ? wp_unslash( $_SERVER['REQUEST_URI'] ) : '';
		$kind = RatePolicy::classify(
			(string) wp_parse_url( $uri, PHP_URL_PATH ),
			isset( $_GET['rest_route'] ) && '' !== sanitize_text_field( wp_unslash( $_GET['rest_route'] ) ), // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Only tested for being empty.
			(string) wp_parse_url( home_url( rest_get_url_prefix() . '/' ), PHP_URL_PATH ),
			(string) ( $GLOBALS['pagenow'] ?? '' ),
			is_string( $_SERVER['REQUEST_METHOD'] ?? null ) ? sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '',
			defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST,
			wp_doing_ajax()
		);
		if ( 'rest' === $kind ) {
			// A blocked address is refused right away. The count waits for REST authentication, or runs on `wp` when REST never answers.
			$this->gate( 'rest', false );
			add_filter( 'rest_authentication_errors', array( $this, 'rest' ), 101 );
			add_action( 'wp', fn() => $this->gate( 'page' ) );
			return;
		}
		$this->gate( $kind );
	}

	public function rest( mixed $errors ): mixed {
		if ( ! is_user_logged_in() ) {
			$this->gate( 'rest' );
		}
		return $errors;
	}

	/** True for addresses that are never counted or blocked: unknown, on the never-limit list, or the site calling itself. */
	public static function exempt( WordPressClientAddress $client, array $allow ): bool {
		$address = $client->address( $_SERVER );
		if ( null === $address || RatePolicy::listed( $address, $allow ) ) {
			return true;
		}
		$peer   = is_string( $_SERVER['REMOTE_ADDR'] ?? null ) ? (string) Cidr::canonical( sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) ) : '';
		$server = is_string( $_SERVER['SERVER_ADDR'] ?? null ) ? (string) Cidr::canonical( sanitize_text_field( wp_unslash( $_SERVER['SERVER_ADDR'] ) ) ) : '';
		return RatePolicy::fromServer( explode( '/', $peer )[0], $address, explode( '/', $server )[0] );
	}

	private function gate( string $kind, bool $count = true ): void {
		$settings = self::settings();
		$client   = new WordPressClientAddress();
		if ( $this->counted || self::exempt( $client, $settings['allow'] ) ) {
			return;
		}
		$store = new BotCounterStore( $GLOBALS['wpdb'] );
		$now   = time();
		$block = $client->key( wp_salt( 'auth' ) . self::BLOCK_SALT, true )->fromServer( $_SERVER );
		if ( null === $block ) {
			return;
		}
		if ( 'block' === $settings['mode'] ) {
			$until = $store->blockedUntil( $block, $now );
			if ( $until > 0 ) {
				self::deny( $until - $now );
			}
		}
		if ( ! $count ) {
			return;
		}
		$this->counted = true;
		$key           = $client->key( wp_salt( 'auth' ) . ':bot:rate:' . ( 'xmlrpc' === $kind ? 'rest' : $kind ), true )->fromServer( $_SERVER );
		if ( null === $key ) {
			return;
		}
		$limit    = RatePolicy::limit( $settings, $kind );
		$count    = self::count( $store, $key, $now );
		$decision = RatePolicy::decide( $settings['mode'], $count, $limit );
		if ( 'none' === $decision ) {
			return;
		}
		// A fixed one-minute window counts up by one, so only the first request over the limit logs.
		if ( $limit + 1 === $count ) {
			self::remember( $block, $now );
			( new ActivityHooks( new ActivityRepository( $GLOBALS['wpdb'] ) ) )->record( 'block' === $decision ? 'rate_blocked' : 'rate_limited', 0, $kind );
		}
		if ( 'block' === $decision ) {
			$seconds = $settings['block'] * MINUTE_IN_SECONDS;
			$store->block( $block, $now + $seconds, $now );
			self::deny( $seconds );
		}
	}

	/** One counter write per request: the object cache when there is one, otherwise the shared table. */
	private static function count( BotCounterStore $store, string $key, int $now ): ?int {
		if ( ! wp_using_ext_object_cache() ) {
			// Leaves room in the shared table so a flood of page counters can't switch off the form and scanner counters.
			return $store->record( $key, self::WINDOW, $now, 7000 );
		}
		$bucket = $key . ':' . intdiv( $now, self::WINDOW );
		wp_cache_add( $bucket, 0, 'amsec_rate', 2 * self::WINDOW );
		$count = wp_cache_incr( $bucket, 1, 'amsec_rate' );
		return false === $count ? null : (int) $count;
	}

	/** Keeps the last 24 hours of limited addresses (salted keys only) for the count on the settings screen. */
	private static function remember( string $key, int $now ): void {
		$recent                          = get_option( self::RECENT, array() );
		$recent                          = is_array( $recent ) ? array_filter( $recent, static fn( mixed $at ): bool => is_int( $at ) && $at > $now - DAY_IN_SECONDS ) : array();
		$recent[ substr( $key, 0, 16 ) ] = $now;
		arsort( $recent );
		update_option( self::RECENT, array_slice( $recent, 0, 500, true ), false );
	}

	/**
	 * True when this request came through a proxy that the site does not trust yet. Then every visitor
	 * shares the proxy address, and Block would pause them all together.
	 */
	public static function proxyUnresolved(): bool {
		$forwarded = false;
		foreach ( array( 'HTTP_X_FORWARDED_FOR', 'HTTP_CF_CONNECTING_IP', 'HTTP_X_REAL_IP', 'HTTP_FORWARDED' ) as $header ) {
			$forwarded = $forwarded || ( is_string( $_SERVER[ $header ] ?? null ) && '' !== $_SERVER[ $header ] );
		}
		$peer = is_string( $_SERVER['REMOTE_ADDR'] ?? null ) ? Cidr::canonical( sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) ) : null;
		return $forwarded && null !== $peer && ( new WordPressClientAddress() )->address( $_SERVER ) === explode( '/', $peer )[0];
	}

	public static function recentCount( int $now ): int {
		$recent = get_option( self::RECENT, array() );
		return is_array( $recent ) ? count( array_filter( $recent, static fn( mixed $at ): bool => is_int( $at ) && $at > $now - DAY_IN_SECONDS ) ) : 0;
	}

	private static function deny( int $seconds ): void {
		status_header( 429 );
		nocache_headers();
		header( 'Retry-After: ' . max( 1, $seconds ) );
		header( 'Content-Type: text/plain; charset=utf-8' );
		echo esc_html__( 'Too many requests from your address. Please wait a few minutes and try again.', 'amsec-security-scanner' );
		exit;
	}

	public function handle(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'amsec-security-scanner' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'amsec_rate_limits' );
		$raw = array();
		foreach ( array( 'mode', 'page', 'rest', 'login', 'block', 'allow' ) as $field ) {
			$key           = 'amsec_rate_' . $field;
			$raw[ $field ] = isset( $_POST[ $key ] ) && is_string( $_POST[ $key ] ) ? sanitize_textarea_field( wp_unslash( $_POST[ $key ] ) ) : null;
		}
		list( $settings, $errors ) = RatePolicy::validate( $raw );
		$url                       = admin_url( 'admin.php?page=amsec-traffic-guard' );
		if ( null === $settings ) {
			$args = array( 'amsec_rate_error' => isset( $errors['lines'] ) ? 'lines' : ( isset( $errors['too_many'] ) ? 'too_many' : 'numbers' ) );
			if ( isset( $errors['lines'] ) ) {
				$args['amsec_rate_lines'] = implode( ',', array_slice( $errors['lines'], 0, 20 ) );
			}
			wp_safe_redirect( add_query_arg( $args, $url ) . '#amsec-rate' );
			exit;
		}
		if ( 'block' === $settings['mode'] && self::proxyUnresolved() ) {
			wp_safe_redirect( add_query_arg( 'amsec_rate_error', 'proxy', $url ) . '#amsec-rate' );
			exit;
		}
		update_option( self::OPTION, $settings, true );
		( new ActivityHooks( new ActivityRepository( $GLOBALS['wpdb'] ) ) )->record( 'security_setting_changed', 0, 'rate-limits-' . $settings['mode'] );
		wp_safe_redirect( \AmazingPlugins\Security\Admin\Brand::saved( $url ) . '#amsec-rate' );
		exit;
	}

	public function render(): void {
		$settings = self::settings();
		$mode     = $settings['mode'];
		$choices  = array(
			'off'   => __( 'Off', 'amsec-security-scanner' ),
			'watch' => __( 'Watch', 'amsec-security-scanner' ),
			'block' => __( 'Block', 'amsec-security-scanner' ),
		);
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- Read-only flash values after a nonce-checked save.
		$error = isset( $_GET['amsec_rate_error'] ) ? sanitize_key( wp_unslash( $_GET['amsec_rate_error'] ) ) : '';
		$lines = isset( $_GET['amsec_rate_lines'] ) ? array_map( 'intval', explode( ',', sanitize_text_field( wp_unslash( $_GET['amsec_rate_lines'] ) ) ) ) : array();
		// phpcs:enable
		$count = self::recentCount( time() );
		echo '<div class="wrap amsec-security-scanner-admin amsec-brief" id="amsec-rate">';
		echo '<details class="amsec-more"' . ( '' !== $error ? ' open' : '' ) . '><summary>' . esc_html__( 'Advanced: rate limiting', 'amsec-security-scanner' ) . '</summary>';
		if ( 'lines' === $error ) {
			/* translators: %s: comma-separated line numbers. */
			echo '<div class="notice notice-error inline"><p>' . esc_html( sprintf( __( 'Nothing was saved. These never-limit lines are not valid IP addresses or ranges: %s.', 'amsec-security-scanner' ), implode( ', ', array_filter( $lines ) ) ) ) . '</p></div>';
		} elseif ( 'too_many' === $error ) {
			/* translators: %d: maximum number of entries. */
			echo '<div class="notice notice-error inline"><p>' . esc_html( sprintf( __( 'Nothing was saved. The never-limit list holds up to %d entries.', 'amsec-security-scanner' ), RatePolicy::MAX_ALLOW ) ) . '</p></div>';
		} elseif ( 'proxy' === $error || self::proxyUnresolved() ) {
			echo '<div class="notice notice-' . ( 'proxy' === $error ? 'error' : 'warning' ) . ' inline"><p>' . esc_html__( 'This site seems to sit behind a proxy or CDN that is not set up under Trusted proxies. Every visitor would share its address, so Block is not allowed until trusted proxies are set up.', 'amsec-security-scanner' ) . '</p></div>';
		} elseif ( '' !== $error ) {
			echo '<div class="notice notice-error inline"><p>' . esc_html__( 'Nothing was saved. Use numbers inside the ranges shown.', 'amsec-security-scanner' ) . '</p></div>';
		}
		echo '<p class="amsec-brief-status"><span class="amsec-pill' . ( 'off' === $mode ? ' is-off' : ' is-on' ) . '">' . esc_html( $choices[ $mode ] ) . '</span>';
		echo esc_html__( 'Limits how many requests one guest address can send each minute.', 'amsec-security-scanner' ) . '</p>';
		echo '<ul class="amsec-facts"><li><strong>' . esc_html( number_format_i18n( $count ) ) . '</strong> ';
		echo esc_html( _n( 'address went over a limit in the last 24 hours', 'addresses went over a limit in the last 24 hours', $count, 'amsec-security-scanner' ) ) . '</li></ul>';
		echo '<p>' . esc_html__( 'Watch writes one line to the activity log when an address goes over a limit. Block also answers that address with a "too many requests" error until the block ends. Signed-in people, cron, WP-CLI, the server itself and the never-limit list are not counted. Blocks are shared with the scanner guard.', 'amsec-security-scanner' ) . '</p>';
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="amsec_rate_limits">';
		wp_nonce_field( 'amsec_rate_limits' );
		echo '<p><label for="amsec-rate-mode">' . esc_html__( 'Rate limiting', 'amsec-security-scanner' ) . '</label> <select id="amsec-rate-mode" name="amsec_rate_mode">';
		foreach ( $choices as $value => $choice ) {
			echo '<option value="' . esc_attr( $value ) . '"' . selected( $mode, $value, false ) . '>' . esc_html( $choice ) . '</option>';
		}
		echo '</select></p>';
		$labels = array(
			'page'  => __( 'Page requests per minute', 'amsec-security-scanner' ),
			'rest'  => __( 'REST and XML-RPC requests per minute', 'amsec-security-scanner' ),
			'login' => __( 'wp-login.php and admin-ajax.php posts per minute', 'amsec-security-scanner' ),
			'block' => __( 'Block length in minutes', 'amsec-security-scanner' ),
		);
		foreach ( $labels as $field => $label ) {
			$bound = RatePolicy::BOUNDS[ $field ];
			echo '<p><label for="amsec-rate-' . esc_attr( $field ) . '">' . esc_html( $label ) . '</label> <input type="number" class="small-text" id="amsec-rate-' . esc_attr( $field ) . '" name="amsec_rate_' . esc_attr( $field ) . '" value="' . esc_attr( (string) $settings[ $field ] ) . '" min="' . esc_attr( (string) $bound[1] ) . '" max="' . esc_attr( (string) $bound[2] ) . '" required> ';
			/* translators: 1: smallest allowed number, 2: largest allowed number. */
			echo '<span class="description">' . esc_html( sprintf( __( '%1$d to %2$d', 'amsec-security-scanner' ), $bound[1], $bound[2] ) ) . '</span></p>';
		}
		echo '<p><label for="amsec-rate-allow">' . esc_html__( 'Never limit these addresses (one IP or CIDR range per line, up to 50)', 'amsec-security-scanner' ) . '</label><br><textarea id="amsec-rate-allow" name="amsec_rate_allow" rows="4" class="large-text code" maxlength="4096">' . esc_html( implode( "\n", $settings['allow'] ) ) . '</textarea></p>';
		echo '<p>';
		submit_button( __( 'Save rate limiting', 'amsec-security-scanner' ), 'secondary', 'amsec-rate-save', false );
		echo '</p></form></details></div>';
	}
}
