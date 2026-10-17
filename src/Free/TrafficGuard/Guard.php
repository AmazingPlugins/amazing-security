<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Free\TrafficGuard;

defined( 'ABSPATH' ) || exit;

/** Runs the request checks and keeps the local log option in sync. */
final class Guard {
	public function enforce(): void {
		$server = $this->snapshot();
		$this->record( $server );
		$lists = new BlockList();
		if ( $lists->blocked( $this->list( Options::HOSTNAMES ), $this->list( Options::AGENTS ), $this->list( Options::REFERRERS ), $server, $this->canManage() ) ) {
			$this->deny( __( 'Request blocked.', 'amazing-security' ) );
		}
		$hotlink = new Hotlink();
		if ( $hotlink->blocked( $this->enabled( Options::HOTLINK ), $server, $this->siteHost() ) ) {
			$this->deny( __( 'Image request blocked.', 'amazing-security' ) );
		}
	}

	public function snapshot(): array {
		$server = array(
			'REMOTE_ADDR'     => $this->serverValue( 'REMOTE_ADDR' ),
			'REQUEST_URI'     => $this->serverValue( 'REQUEST_URI' ),
			'SCRIPT_NAME'     => $this->serverValue( 'SCRIPT_NAME' ),
			'HTTP_HOST'       => $this->serverValue( 'HTTP_HOST' ),
			'HTTP_USER_AGENT' => $this->serverValue( 'HTTP_USER_AGENT' ),
			'HTTP_REFERER'    => $this->serverValue( 'HTTP_REFERER' ),
		);
		if ( ( function_exists( 'wp_doing_cron' ) && wp_doing_cron() ) || ( defined( 'DOING_CRON' ) && DOING_CRON ) ) {
			$server['AMSEC_CRON'] = '1';
		}
		$rest = ( defined( 'REST_REQUEST' ) && REST_REQUEST ) || ( function_exists( 'wp_is_serving_rest_request' ) && wp_is_serving_rest_request() );
		if ( $rest ) {
			$server['AMSEC_REST'] = '1';
		}
		$cli = in_array( PHP_SAPI, array( 'cli', 'phpdbg' ), true ) || ( defined( 'WP_CLI' ) && WP_CLI );
		if ( $cli ) {
			$server['AMSEC_CLI'] = '1';
		}
		return $server;
	}

	public static function syncLog( mixed $value ): void {
		if ( '1' === (string) $value ) {
			if ( function_exists( 'get_option' ) && false === get_option( Options::LIVE_ROWS, false ) ) {
				add_option( Options::LIVE_ROWS, array(), '', false );
			}
			return;
		}
		if ( function_exists( 'delete_option' ) ) {
			delete_option( Options::LIVE_ROWS );
		}
	}

	public static function syncFromUpdate( mixed $previous, mixed $value ): void {
		if ( (string) $previous === (string) $value ) {
			return;
		}
		self::syncLog( $value );
	}

	public static function syncFromAdd( mixed $name, mixed $value ): void {
		if ( Options::LIVE !== (string) $name ) {
			return;
		}
		self::syncLog( $value );
	}

	/**
	 * @param array<string, string> $server
	 */
	private function record( array $server ): void {
		$log = new LiveTraffic();
		if ( ! $log->shouldStore( $this->enabled( Options::LIVE ), $server ) ) {
			return;
		}
		$row = $log->row( $server, time() );
		if ( null === $row || ! function_exists( 'get_option' ) || ! function_exists( 'update_option' ) ) {
			return;
		}
		try {
			$stored = get_option( Options::LIVE_ROWS, array() );
			$rows   = is_array( $stored ) ? $stored : array();
			update_option( Options::LIVE_ROWS, $log->append( $rows, $row ), false );
		} catch ( \Throwable $exception ) {
			if ( $exception instanceof \Throwable ) {
				return;
			}
		}
	}

	private function deny( string $message ): void {
		wp_die( esc_html( $message ), '', array( 'response' => 403 ) );
	}

	private function canManage(): bool {
		return function_exists( 'current_user_can' ) && current_user_can( 'manage_options' );
	}

	private function enabled( string $name ): bool {
		return '1' === $this->list( $name );
	}

	private function list( string $name ): string {
		if ( ! function_exists( 'get_option' ) ) {
			return '';
		}
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

	private function siteHost(): string {
		if ( ! function_exists( 'home_url' ) || ! function_exists( 'wp_parse_url' ) ) {
			return '';
		}
		try {
			$parts = wp_parse_url( home_url() );
		} catch ( \Throwable $exception ) {
			return $exception instanceof \Throwable ? '' : '';
		}
		if ( ! is_array( $parts ) ) {
			return '';
		}
		$host = $parts['host'] ?? '';
		return is_string( $host ) ? strtolower( $host ) : '';
	}

	private function serverValue( string $key ): string {
		if ( ! isset( $_SERVER[ $key ] ) || ! is_string( $_SERVER[ $key ] ) ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Sanitized on the return below.
			return '';
		}
		return sanitize_text_field( wp_unslash( $_SERVER[ $key ] ) );
	}
}
