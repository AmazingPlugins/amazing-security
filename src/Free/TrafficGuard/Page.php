<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Free\TrafficGuard;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Admin\ScreenTabs;
use AmazingPlugins\Security\Bots\BotSettings;
use AmazingPlugins\Security\Firewall\RestRateSettings;
use AmazingPlugins\Security\Free\Comments\Page as CommentChecks;
use AmazingPlugins\Security\Free\Detect\Module as PreciseBlock;
use AmazingPlugins\Security\Headers\HeaderPage;
use AmazingPlugins\Security\Network\NetworkSettings;
use AmazingPlugins\Security\Proxy\ProxySettings;
use AmazingPlugins\Security\Traffic\TrafficSettings;

/** Traffic controls screen. Posts to admin-post.php. */
final class Page {
	public function register(): void {
		add_submenu_page(
			'amazing-security',
			__( 'Traffic', 'amazingplugins-security-scanner' ),
			__( 'Traffic', 'amazingplugins-security-scanner' ),
			'manage_options',
			'amsec-traffic-guard',
			array( $this, 'render' )
		);
		add_action( 'admin_enqueue_scripts', array( $this, 'assets' ) );
	}

	public function assets(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only admin screen slug.
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( (string) $_GET['page'] ) ) : '';
		if ( 'amsec-traffic-guard' !== $page ) {
			return;
		}
		wp_enqueue_script( 'amazing-security-traffic', plugins_url( 'assets/admin-traffic.js', AMAZING_SECURITY_FILE ), array(), '0.1.0', true );
		wp_localize_script(
			'amazing-security-traffic',
			'amsecTrafficExamples',
			array(
				'fields'   => array(
					'host'     => Options::HOSTNAMES,
					'agent'    => Options::AGENTS,
					'referrer' => Options::REFERRERS,
				),
				'host'     => Examples::hostnames(),
				'agent'    => Examples::agents(),
				'referrer' => Examples::referrers(),
				'added'    => __( 'Those lines are in the boxes. Save writes them.', 'amazingplugins-security-scanner' ),
				'already'  => __( 'Those lines are already in the boxes.', 'amazingplugins-security-scanner' ),
				'full'     => __( 'A box already has 20 lines.', 'amazingplugins-security-scanner' ),
			)
		);
	}

	public function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'amazingplugins-security-scanner' ), '', array( 'response' => 403 ) );
		}
		$hostnames = $this->stored( Options::HOSTNAMES );
		$agents    = $this->stored( Options::AGENTS );
		$referrers = $this->stored( Options::REFERRERS );
		$live      = $this->stored( Options::LIVE );
		$hotlink   = $this->stored( Options::HOTLINK );
		$notice    = $this->notice();
		echo '<div class="wrap amazing-security-admin">';
		if ( '' !== $notice ) {
			echo '<div class="notice notice-info"><p>' . esc_html( $notice ) . '</p></div>';
		}
		ScreenTabs::bar(
			array(
				'bots'    => __( 'Comments and registration', 'amazingplugins-security-scanner' ),
				'lists'   => __( 'Lists', 'amazingplugins-security-scanner' ),
				'rest'    => __( 'REST rate controls', 'amazingplugins-security-scanner' ),
				'precise' => __( 'Precise blocks', 'amazingplugins-security-scanner' ),
				'network' => __( 'Network controls', 'amazingplugins-security-scanner' ),
				'headers' => __( 'Security headers', 'amazingplugins-security-scanner' ),
				'proxies' => __( 'Trusted proxies', 'amazingplugins-security-scanner' ),
				'history' => __( 'History', 'amazingplugins-security-scanner' ),
			)
		);
		ScreenTabs::panel( 'bots', true );
		( new BotSettings() )->render();
		CommentChecks::render();
		( new \AmazingPlugins\Security\Bots\ScannerGuard() )->render();
		( new \AmazingPlugins\Security\Bots\RateLimiter() )->render();
		ScreenTabs::close();
		ScreenTabs::panel( 'lists', false );
		echo '<p>' . esc_html__( 'Block lists, the live log, and the hotlink check stay off until you turn them on.', 'amazingplugins-security-scanner' ) . '</p>';
		echo '<section class="amsec-overview"><form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
		echo '<input type="hidden" name="action" value="amsec_traffic_guard">';
		wp_nonce_field( 'amsec_traffic_guard_save' );
		echo '<h2>' . esc_html__( 'Block lists', 'amazingplugins-security-scanner' ) . '</h2>';
		echo '<p>' . esc_html__( 'One entry per line, 20 lines at most, 120 characters each. An empty box stays off. Host lines must match the whole hostname. A browser line blocks any browser string that contains it. Referrer lines must start with http:// or https://. Administrators are not blocked. A list that matches this request is not saved.', 'amazingplugins-security-scanner' ) . '</p>';
		echo '<p class="amsec-example-actions"><button type="button" class="button" id="amsec-put-examples">' . esc_html__( 'Put recommended examples', 'amazingplugins-security-scanner' ) . '</button></p>';
		echo '<p id="amsec-example-note" class="amsec-example-note" hidden></p>';
		$this->textarea( Options::HOSTNAMES, __( 'Hostname block list', 'amazingplugins-security-scanner' ), $hostnames );
		$this->textarea( Options::AGENTS, __( 'Browser block list', 'amazingplugins-security-scanner' ), $agents );
		$this->textarea( Options::REFERRERS, __( 'Referrer block list', 'amazingplugins-security-scanner' ), $referrers );
		echo '<h2>' . esc_html__( 'Live log', 'amazingplugins-security-scanner' ) . '</h2>';
		echo '<p>' . esc_html__( 'When this is on, up to 500 rows stay in the WordPress database. Each row stores the REMOTE_ADDR value (45 characters at most), the request path without the query string (200 characters at most), and a UTC unix time. wp-admin, cron, CLI, and REST requests are skipped. Turning this off stops recording and deletes the rows.', 'amazingplugins-security-scanner' ) . '</p>';
		$this->toggle( Options::LIVE, __( 'Live log', 'amazingplugins-security-scanner' ), $live );
		echo '<h2>' . esc_html__( 'Hotlink check', 'amazingplugins-security-scanner' ) . '</h2>';
		echo '<p>' . esc_html__( 'When this is on, an Apache rule is written in the uploads folder. jpg, jpeg, png, gif, and webp files are refused when the referrer is another site. An empty referrer is allowed. A referrer on this host is allowed. Nginx ignores that file.', 'amazingplugins-security-scanner' ) . '</p>';
		$this->toggle( Options::HOTLINK, __( 'Hotlink check', 'amazingplugins-security-scanner' ), $hotlink );
		submit_button( __( 'Save traffic controls', 'amazingplugins-security-scanner' ) );
		echo '</form></section>';
		$this->logTable( '1' === $live );
		ScreenTabs::close();
		ScreenTabs::panel( 'precise', false );
		PreciseBlock::render();
		ScreenTabs::close();
		ScreenTabs::panel( 'headers', false );
		( new HeaderPage() )->render();
		ScreenTabs::close();
		ScreenTabs::panel( 'rest', false );
		( new RestRateSettings() )->render();
		ScreenTabs::close();
		ScreenTabs::panel( 'network', false );
		( new NetworkSettings() )->render();
		ScreenTabs::close();
		ScreenTabs::panel( 'proxies', false );
		( new ProxySettings() )->render();
		ScreenTabs::close();
		ScreenTabs::panel( 'history', false );
		( new TrafficSettings() )->render();
		ScreenTabs::close();
		echo '</div>';
	}

	public function save(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'amazingplugins-security-scanner' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'amsec_traffic_guard_save' );
		$post = wp_unslash( $_POST ); // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Nonce checked above. Each field is sanitized before it is saved.
		if ( ! is_array( $post ) ) {
			$post = array();
		}
		$server    = ( new Guard() )->snapshot();
		$lists     = new BlockList();
		$hostnames = $lists->prepare( $this->postedList( $post, Options::HOSTNAMES ), 'host', $server['HTTP_HOST'] ?? '' );
		$agents    = $lists->prepare( $this->postedList( $post, Options::AGENTS ), 'agent', $server['HTTP_USER_AGENT'] ?? '' );
		$referrers = $lists->prepare( $this->postedList( $post, Options::REFERRERS ), 'referrer', $server['HTTP_REFERER'] ?? '' );
		foreach ( array( $hostnames, $agents, $referrers ) as $result ) {
			if ( empty( $result['ok'] ) ) {
				$this->redirect( is_string( $result['error'] ?? null ) ? $result['error'] : 'count' );
			}
		}
		$live    = $this->postedFlag( $post, Options::LIVE );
		$hotlink = $this->postedFlag( $post, Options::HOTLINK );
		try {
			update_option( Options::HOSTNAMES, $hostnames['value'] );
			update_option( Options::AGENTS, $agents['value'] );
			update_option( Options::REFERRERS, $referrers['value'] );
			update_option( Options::LIVE, $live );
			update_option( Options::HOTLINK, $hotlink );
			Guard::syncLog( $live );
			$this->syncHotlink( $hotlink );
		} catch ( \Throwable $exception ) {
			if ( $exception instanceof \Throwable ) {
				$this->redirect( 'save' );
			}
		}
		$this->redirect( 'saved' );
	}

	private function textarea( string $name, string $label, string $value ): void {
		echo '<p><label for="' . esc_attr( $name ) . '">' . esc_html( $label ) . '</label><br>';
		echo '<textarea name="' . esc_attr( $name ) . '" id="' . esc_attr( $name ) . '" rows="6" cols="60" maxlength="3000">';
		echo esc_textarea( $value );
		echo '</textarea></p>';
	}

	private function toggle( string $name, string $label, string $value ): void {
		echo '<p><label for="' . esc_attr( $name ) . '">' . esc_html( $label ) . ' ';
		echo '<select name="' . esc_attr( $name ) . '" id="' . esc_attr( $name ) . '">';
		echo '<option value="0"' . selected( '1' === $value ? '1' : '0', '0', false ) . '>' . esc_html__( 'Off', 'amazingplugins-security-scanner' ) . '</option>';
		echo '<option value="1"' . selected( '1' === $value ? '1' : '0', '1', false ) . '>' . esc_html__( 'On', 'amazingplugins-security-scanner' ) . '</option>';
		echo '</select></label></p>';
	}

	private function logTable( bool $enabled ): void {
		echo '<h2>' . esc_html__( 'Latest 50 rows', 'amazingplugins-security-scanner' ) . '</h2>';
		if ( ! $enabled ) {
			echo '<p>' . esc_html__( 'Logging is off.', 'amazingplugins-security-scanner' ) . '</p>';
			return;
		}
		try {
			$stored = get_option( Options::LIVE_ROWS, array() );
		} catch ( \Throwable $exception ) {
			if ( $exception instanceof \Throwable ) {
				echo '<p>' . esc_html__( 'The log could not be read.', 'amazingplugins-security-scanner' ) . '</p>';
				return;
			}
		}
		$rows = ( new LiveTraffic() )->latest( is_array( $stored ) ? $stored : array(), LiveTraffic::VIEW );
		if ( array() === $rows ) {
			echo '<p>' . esc_html__( 'No rows stored.', 'amazingplugins-security-scanner' ) . '</p>';
			return;
		}
		echo '<table class="widefat striped"><thead><tr>';
		echo '<th scope="col">' . esc_html__( 'Time (UTC)', 'amazingplugins-security-scanner' ) . '</th>';
		echo '<th scope="col">' . esc_html__( 'Address', 'amazingplugins-security-scanner' ) . '</th>';
		echo '<th scope="col">' . esc_html__( 'Path', 'amazingplugins-security-scanner' ) . '</th>';
		echo '</tr></thead><tbody>';
		foreach ( $rows as $row ) {
			$stamp = $row['time'] > 0 ? gmdate( 'Y-m-d H:i:s', $row['time'] ) : __( 'Unknown', 'amazingplugins-security-scanner' );
			echo '<tr><td>' . esc_html( $stamp ) . '</td><td>' . esc_html( $row['ip'] ) . '</td><td>' . esc_html( $row['path'] ) . '</td></tr>';
		}
		echo '</tbody></table>';
	}

	private function notice(): string {
		$status = isset( $_GET['amsec_traffic_guard'] ) ? sanitize_key( wp_unslash( (string) $_GET['amsec_traffic_guard'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only status flag after a verified save redirect.
		$notes  = array(
			'saved'  => __( 'Traffic controls saved.', 'amazingplugins-security-scanner' ),
			'count'  => __( 'Use 20 entries or fewer in each list.', 'amazingplugins-security-scanner' ),
			'length' => __( 'Use 120 characters or fewer for each entry.', 'amazingplugins-security-scanner' ),
			'prefix' => __( 'Referrer entries have to start with http:// or https://.', 'amazingplugins-security-scanner' ),
			'self'   => __( 'That list matches this request, so nothing was saved.', 'amazingplugins-security-scanner' ),
			'save'   => __( 'The traffic controls could not be saved.', 'amazingplugins-security-scanner' ),
		);
		return $notes[ $status ] ?? '';
	}

	/**
	 * @param array<mixed> $post
	 */
	private function postedList( array $post, string $key ): string {
		$raw = $post[ $key ] ?? '';
		if ( ! is_string( $raw ) ) {
			return '';
		}
		$parts = preg_split( "/\r\n|\n|\r/", $raw );
		if ( ! is_array( $parts ) ) {
			return '';
		}
		$lines = array();
		foreach ( $parts as $part ) {
			if ( ! is_string( $part ) ) {
				continue;
			}
			$lines[] = sanitize_text_field( $part );
		}
		return implode( "\n", $lines );
	}

	/**
	 * @param array<mixed> $post
	 */
	private function postedFlag( array $post, string $key ): string {
		$value = $post[ $key ] ?? '0';
		return is_string( $value ) && '1' === $value ? '1' : '0';
	}

	private function stored( string $name ): string {
		try {
			$value = get_option( $name, '' );
		} catch ( \Throwable $exception ) {
			return $exception instanceof \Throwable ? '' : '';
		}
		if ( is_string( $value ) || is_int( $value ) ) {
			return (string) $value;
		}
		return '';
	}

	public function syncHotlink( string $flag ): void {
		$uploads = wp_upload_dir( null, false );
		$dir     = empty( $uploads['error'] ) && is_string( $uploads['basedir'] ?? null ) ? $uploads['basedir'] : '';
		if ( '' === $dir || is_link( $dir ) || ! is_dir( $dir ) ) {
			return;
		}
		$path     = $dir . '/.htaccess';
		$existing = is_file( $path ) ? $this->readFile( $path ) : '';
		if ( null === $existing ) {
			return;
		}
		$host = function_exists( 'home_url' ) ? wp_parse_url( home_url(), PHP_URL_HOST ) : '';
		$next = HotlinkRule::apply( $existing, is_string( $host ) ? $host : '', '1' === $flag );
		if ( $next === $existing ) {
			return;
		}
		if ( '' === $next ) {
			if ( is_file( $path ) ) {
				wp_delete_file( $path );
			}
			return;
		}
		$this->writeFile( $path, $next );
	}

	private function readFile( string $path ): ?string {
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local uploads rule, not a remote request.
		$contents = file_get_contents( $path );
		return is_string( $contents ) ? $contents : null;
	}

	private function writeFile( string $path, string $contents ): void {
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Confirmed local uploads rule.
		file_put_contents( $path, $contents );
	}

	private function redirect( string $code ): void {
		wp_safe_redirect( admin_url( 'admin.php?page=amsec-traffic-guard&amsec_traffic_guard=' . rawurlencode( $code ) . '#lists' ) );
		exit;
	}
}
