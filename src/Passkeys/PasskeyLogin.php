<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Passkeys;

/** Anonymous ceremonies are bound to exact origin, an HttpOnly cookie and a one-use signed challenge. */
final class PasskeyLogin {
	public function __construct( private readonly object $db ) {}
	private function configuration(): ?array {
		$configuration = ( new PasskeyRuntime( $this->db ) )->configuration();
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Exact method/origin validation must not normalize hostile input.
		$server = array(
			'REQUEST_METHOD' => isset( $_SERVER['REQUEST_METHOD'] ) ? wp_unslash( $_SERVER['REQUEST_METHOD'] ) : null,
			'HTTP_ORIGIN'    => isset( $_SERVER['HTTP_ORIGIN'] ) ? wp_unslash( $_SERVER['HTTP_ORIGIN'] ) : null,
		);
		return 0 === get_current_user_id() && null !== $configuration && PasskeyRequestGate::request( $configuration['context'], $server, is_ssl() ) ? $configuration : null;
	}
	public function begin( int $now ): ?array {
		try {
			$config = $this->configuration();
			if ( null === $config ) {
				return null; }
			$key   = ( new \AmazingPlugins\Security\Proxy\WordPressClientAddress() )->key( wp_salt( 'auth' ) . ':passkey:' . $config['policy']['revision'] . ':' . $config['context']->fingerprint() )->fromServer( $_SERVER );
			$count = null === $key ? null : ( new \AmazingPlugins\Security\Bots\BotCounterStore( $this->db ) )->record( $key, 300, $now );
			if ( null === $count || $count > 20 ) {
				return null; }
			$binding = ( new PasskeyRuntime( $this->db ) )->binding( true );
			if ( null === $binding ) {
				return null; }
			$ticket    = random_bytes( 32 );
			$challenge = Base64Url::encode( random_bytes( 32 ) );
			$pending   = array(
				'version'          => 1,
				'purpose'          => 'login',
				'user_id'          => 0,
				'session_hash'     => '',
				'account_revision' => '',
				'challenge'        => $challenge,
				'ticket_hash'      => hash( 'sha256', $ticket ),
				'binding_hash'     => hash( 'sha256', $binding ),
				'policy_revision'  => $config['policy']['revision'],
				'context_revision' => $config['context']->fingerprint(),
				'created_at'       => $now,
				'expires_at'       => $now + 300,
			);
			if ( ! ( new PasskeyRepository( $this->db ) )->addPending( $pending, $config['context'], $now ) ) {
				return null; }
			return array(
				'ticket'    => Base64Url::encode( $ticket ),
				'publicKey' => array(
					'challenge'        => $challenge,
					'rpId'             => $config['context']->rpId(),
					'userVerification' => 'required',
					'timeout'          => 120000,
				),
			);
		} catch ( \Throwable $error ) {
			return null; }
	}
	public function finish( array $post, int $now ): ?array {
		try {
			$config  = $this->configuration();
			$ticket  = Base64Url::decode( $post['ticket'] ?? null, 32 );
			$binding = ( new PasskeyRuntime( $this->db ) )->binding();
			if ( null === $config || null === $ticket || 32 !== strlen( $ticket ) || null === $binding || headers_sent() ) {
				return null; }
			$repo    = new PasskeyRepository( $this->db );
			$pending = $repo->claim( $ticket, $binding, 'login', $config['context'], 0, '', $now );
			if ( null === $pending || ! is_string( $post['payload'] ?? null ) || ! is_string( $post['factor'] ?? '' ) || strlen( $post['factor'] ?? '' ) > 128 ) {
				return null; }
			$envelope = ( new PasskeyEnvelope() )->read( $post['payload'], false );
			$loaded   = null === $envelope ? null : $repo->credential( $envelope['credential_id'], $now );
			if ( null === $loaded ) {
				return null; }
			$record = $loaded['record'];
			$handle = ( new PasskeyHandle( $this->db ) )->get( $record['user_id'] );
			if ( null === $handle || $record['context_revision'] !== $config['context']->fingerprint() || ! hash_equals( $record['user_handle'], Base64Url::encode( $handle ) ) ) {
				return null; }
			$verified = ( new PasskeyVerifier() )->assertion( $post['payload'], $config['context'], $pending['challenge'], $envelope['credential_id'], $handle, $record['public_key'], $record['counter'], $record['backup_eligible'] );
			if ( null === $verified ) {
				return null; }
			$gate   = ( new WordPressPasskeyAccount( $this->db ) )->gate();
			$permit = $gate->authorize( $record['user_id'], $post['factor'] ?? '', $now );
			if ( null === $permit || ! $repo->consumeCredential( $loaded, $verified['counter'], $verified['backed_up'], $config['context'], $pending['policy_revision'], $now ) ) {
				return null; }
			$fresh = $this->configuration();
			$user  = $gate->finalCheck( $permit, $now );
			if ( null === $fresh || null === $user || $fresh['context']->fingerprint() !== $pending['context_revision'] || $fresh['policy']['revision'] !== $pending['policy_revision'] || headers_sent() ) {
				return null; }
			return $this->grant( $user ) ? array( 'redirect' => $config['context']->adminUrl() ) : null;
		} catch ( \Throwable $error ) {
			return null; }
	}
	private function grant( \WP_User $user ): bool {
		$token   = '';
		$allowed = false;
		$secure  = static fn() => true;
		$capture = static function ( $cookie, $expire, $expiration, $id, $scheme, $issued ) use ( &$token, $user ) {
			if ( $id === $user->ID ) {
				$token = $issued;
			} };
		$observe = static function ( $send, $expire, $expiration, $id, $scheme, $issued ) use ( &$allowed, &$token, $user ) {
			$allowed = true === $send && $id === $user->ID;
			if ( $id === $user->ID ) {
				$token = $issued;
			} return $send;
		};
		add_filter( 'secure_auth_cookie', $secure, PHP_INT_MAX );
		add_filter( 'secure_logged_in_cookie', $secure, PHP_INT_MAX );
		add_action( 'set_auth_cookie', $capture, PHP_INT_MAX, 6 );
		add_filter( 'send_auth_cookies', $observe, PHP_INT_MAX, 6 );
		$success = false;
		try {
			wp_set_auth_cookie( $user->ID, false, true );
			if ( ! $allowed || '' === $token ) {
				return false; }
			wp_set_current_user( $user->ID );
			do_action( 'wp_login', $user->user_login, $user );
			$success = true;
			return true;
		} finally {
			remove_filter( 'secure_auth_cookie', $secure, PHP_INT_MAX );
			remove_filter( 'secure_logged_in_cookie', $secure, PHP_INT_MAX );
			remove_action( 'set_auth_cookie', $capture, PHP_INT_MAX );
			remove_filter( 'send_auth_cookies', $observe, PHP_INT_MAX );
			if ( ! $success ) {
				if ( '' !== $token ) {
					\WP_Session_Tokens::get_instance( $user->ID )->destroy( $token ); }
				wp_set_current_user( 0 );
				wp_clear_auth_cookie();
			}
		}
	}
	public function beginRequest(): void {
		$this->respond( $this->begin( time() ) ); }
	public function finishRequest(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Anonymous authentication uses exact origin, HttpOnly browser binding and a one-use signed challenge.
		$this->respond( $this->finish( wp_unslash( $_POST ), time() ) );
	}
	private function respond( ?array $result ): void {
		nocache_headers();
		if ( null === $result ) {
			wp_send_json_error( array( 'message' => __( 'Passkey sign-in could not be completed. Try again, or use your password.', 'amazing-security' ) ), 403 ); }
		wp_send_json_success( $result );
	}
}
