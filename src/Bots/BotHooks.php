<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Bots;

defined( 'ABSPATH' ) || exit;

final class BotHooks {
	private bool $checked = false;

	public function mode(): string {
		$value = get_option( 'ironlatch_bot_mode', 'off' );
		return in_array( $value, array( 'off', 'observe', 'block' ), true ) ? $value : 'off';
	}

	public function fields(): void {
		if ( 'off' === $this->mode() || is_user_logged_in() ) {
			return;
		}
		echo '<div hidden aria-hidden="true"><label for="ironlatch-contact-hint">' . esc_html__( 'Leave this field empty', 'ironlatch-security-scanner' ) . '</label><input id="ironlatch-contact-hint" type="text" name="ironlatch_contact_hint" value="" autocomplete="off" tabindex="-1"></div>';
	}

	public function comment( array $data ): array {
		if ( $this->native( 'wp-comments-post.php' ) && $this->reject( 'comment', 20, 300 ) ) {
			wp_die( esc_html__( 'This submission could not be accepted. Leave the hidden field empty and retry later, or contact the site owner.', 'ironlatch-security-scanner' ), '', array( 'response' => 403 ) );
		}
		return $data;
	}

	public function registration( \WP_Error $errors ): \WP_Error {
		if ( $this->native( 'wp-login.php' ) && $this->reject( 'registration', 5, 900 ) ) {
			$errors->add( 'ironlatch_bot_check', __( 'This registration could not be accepted. Retry later or contact the site owner.', 'ironlatch-security-scanner' ) );
		}
		return $errors;
	}

	private function native( string $page ): bool {
		$method = is_string( $_SERVER['REQUEST_METHOD'] ?? null ) ? sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '';
		return ( $GLOBALS['pagenow'] ?? '' ) === $page && 'post' === $method && ! is_user_logged_in() && ! ( defined( 'REST_REQUEST' ) && REST_REQUEST ) && ! ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) && ! ( defined( 'WP_CLI' ) && WP_CLI );
	}

	private function reject( string $kind, int $limit, int $window ): bool {
		$mode = $this->mode();
		if ( 'off' === $mode || $this->checked ) {
			return false;
		}
		$this->checked = true;
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Public native forms have no plugin nonce. Only emptiness is inspected; no input contents are stored or echoed.
		$trap       = isset( $_POST['ironlatch_contact_hint'] ) ? ( is_string( $_POST['ironlatch_contact_hint'] ) ? sanitize_text_field( wp_unslash( $_POST['ironlatch_contact_hint'] ) ) : false ) : null; // A non-string value stays suspicious.
		$suspicious = BotPolicy::trapSuspicious( $trap );
		$key        = ( new \AmazingPlugins\Security\Proxy\WordPressClientAddress() )->key( wp_salt( 'auth' ) . ':bot:' . $kind )->fromServer( \AmazingPlugins\Security\Proxy\WordPressClientAddress::request() );
		$count      = null === $key ? null : ( new BotCounterStore( $GLOBALS['wpdb'] ) )->record( $key, $window, time() );
		return BotPolicy::reject( $mode, $suspicious, $count, $limit );
	}
}
