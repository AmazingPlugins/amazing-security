<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Passkeys;

final class PasskeyRuntime {
	public const COOKIE = '__Host-amsec_passkey';
	public function __construct( private readonly object $db ) {}
	public function context(): ?PasskeyContext {
		$old = $this->db->suppress_errors( true );
		try {
		 // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Origin changes must bypass cached site URL and request Host.
			$url = $this->db->get_var( $this->db->prepare( "SELECT option_value FROM {$this->db->options} WHERE option_name=%s LIMIT 1", 'siteurl' ) );
			return '' === $this->db->last_error && is_string( $url ) ? PasskeyContext::fromSiteUrl( $url ) : null;
		} catch ( \Throwable $error ) {
			return null; } finally {
					$this->db->suppress_errors( $old ); }
	}
	public function configuration( bool $requireEnabled = true ): ?array {
		$context = $this->context();
		$policy  = ( new PasskeyRepository( $this->db ) )->currentPolicy();
		if ( null === $context || null === $policy || ( $requireEnabled && ( ! $policy['enabled'] || ! PasskeyVerifier::available() || ( defined( 'AMSEC_DISABLE_PASSKEYS' ) && AMSEC_DISABLE_PASSKEYS ) ) ) ) {
			return null; }
		return array(
			'context' => $context,
			'policy'  => $policy,
		);
	}
	public function own( array $post, bool $requireEnabled = true ): ?array {
		$configuration = $this->configuration( $requireEnabled );
	 // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Exact origin/method comparison refuses normalization or suffix matching.
		$server = array(
			'REQUEST_METHOD' => isset( $_SERVER['REQUEST_METHOD'] ) ? wp_unslash( $_SERVER['REQUEST_METHOD'] ) : null,
			'HTTP_ORIGIN'    => isset( $_SERVER['HTTP_ORIGIN'] ) ? wp_unslash( $_SERVER['HTTP_ORIGIN'] ) : null,
		);
		if ( null === $configuration || ! PasskeyRequestGate::request( $configuration['context'], $server, is_ssl() ) ) {
			return null; }
		$id       = get_current_user_id();
		$cookieId = wp_validate_auth_cookie( '', 'secure_auth' );
		$loggedId = wp_validate_auth_cookie( '', 'logged_in' );
		$auth     = wp_parse_auth_cookie( '', 'secure_auth' );
		$token    = wp_get_session_token();
		$nonce    = is_string( $post['_wpnonce'] ?? null ) && strlen( $post['_wpnonce'] ) <= 64 && false !== wp_verify_nonce( $post['_wpnonce'], 'amsec_passkey_own_' . $id );
		if ( $loggedId !== $id || ! PasskeyRequestGate::own( $id, is_int( $cookieId ) ? $cookieId : 0, is_array( $auth ) ? (string) $auth['token'] : '', $token, current_user_can( 'read' ), $nonce ) ) {
			return null; }
		return $configuration + array(
			'user_id'      => $id,
			'session_hash' => hash( 'sha256', $token ),
		);
	}
	public function binding( bool $create = false ): ?string {
	 // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Strict canonical binary decoding below; arbitrary cookie text is never stored.
		$raw   = isset( $_COOKIE[ self::COOKIE ] ) ? wp_unslash( $_COOKIE[ self::COOKIE ] ) : null;
		$value = Base64Url::decode( $raw, 32 );
		if ( ! $create && null !== $value && 32 === strlen( $value ) ) {
			return $value; }
		if ( ! $create || ! is_ssl() || headers_sent() ) {
			return null; }
		$value = null !== $value && 32 === strlen( $value ) ? $value : random_bytes( 32 );
		return setcookie(
			self::COOKIE,
			Base64Url::encode( $value ),
			array(
				'expires'  => time() + 300,
				'path'     => '/',
				'secure'   => true,
				'httponly' => true,
				'samesite' => 'Strict',
			)
		) ? $value : null;
	}
}
