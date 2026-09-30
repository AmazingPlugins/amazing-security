<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Passkeys;

final class PasskeyActions {
	public function __construct( private readonly object $db ) {}
	public function begin( array $post, int $now ): ?array {
		try {
			$runtime = new PasskeyRuntime( $this->db );
			$own     = $runtime->own( $post );
			if ( null === $own ) {
				return null; }
			$permit = $this->approve( $post, $own['user_id'], $now );
			if ( null === $permit ) {
				return null; }
			$repository = new PasskeyRepository( $this->db );
			$existing   = $repository->ownCredentials( $own['user_id'], $now );
			if ( null === $existing || count( $existing ) >= 5 ) {
				return null; }
			$handle  = ( new PasskeyHandle( $this->db ) )->get( $own['user_id'], true );
			$binding = $runtime->binding( true );
			if ( null === $handle || null === $binding ) {
				return null; }
			$ticket    = random_bytes( 32 );
			$challenge = Base64Url::encode( random_bytes( 32 ) );
			$pending   = array(
				'version'          => 1,
				'purpose'          => 'enroll',
				'user_id'          => $own['user_id'],
				'session_hash'     => $own['session_hash'],
				'account_revision' => $permit['fingerprint'],
				'challenge'        => $challenge,
				'ticket_hash'      => hash( 'sha256', $ticket ),
				'binding_hash'     => hash( 'sha256', $binding ),
				'policy_revision'  => $own['policy']['revision'],
				'context_revision' => $own['context']->fingerprint(),
				'created_at'       => $now,
				'expires_at'       => $now + 300,
			);
			if ( ! $repository->addPending( $pending, $own['context'], $now ) ) {
				return null; }
			$exclude = array();
			foreach ( $existing as $item ) {
				if ( $item['record']['context_revision'] === $own['context']->fingerprint() ) {
					$exclude[] = array(
						'type' => 'public-key',
						'id'   => $item['record']['credential_id'],
					); }
			}
			$user = $permit['user'];
			return array(
				'ticket'    => Base64Url::encode( $ticket ),
				'publicKey' => array(
					'rp'                     => array(
						'id'   => $own['context']->rpId(),
						'name' => $this->display( get_bloginfo( 'name' ), 'WordPress' ),
					),
					'user'                   => array(
						'id'          => Base64Url::encode( $handle ),
						'name'        => $this->display( $user->user_login, 'Your account' ),
						'displayName' => $this->display( $user->display_name, 'Your account' ),
					),
					'challenge'              => $challenge,
					'pubKeyCredParams'       => array(
						array(
							'type' => 'public-key',
							'alg'  => -7,
						),
					),
					'timeout'                => 120000,
					'attestation'            => 'none',
					'authenticatorSelection' => array(
						'residentKey'        => 'required',
						'requireResidentKey' => true,
						'userVerification'   => 'required',
					),
					'excludeCredentials'     => $exclude,
					'extensions'             => new \stdClass(),
				),
			);
		} catch ( \Throwable $error ) {
			return null; }
	}
	public function finish( array $post, int $now ): bool {
		try {
			$runtime = new PasskeyRuntime( $this->db );
			$own     = $runtime->own( $post );
			$ticket  = Base64Url::decode( $post['ticket'] ?? null, 32 );
			$binding = $runtime->binding();
			if ( null === $own || null === $ticket || strlen( $ticket ) !== 32 || null === $binding ) {
				return false; }
			$repository = new PasskeyRepository( $this->db );
			$pending    = $repository->claim( $ticket, $binding, 'enroll', $own['context'], $own['user_id'], $own['session_hash'], $now );
			if ( null === $pending || ! is_string( $post['payload'] ?? null ) || strlen( $post['payload'] ) > 98304 || ! is_string( $post['label'] ?? null ) || strlen( $post['label'] ) > 80 ) {
				return false; }
			$gate   = ( new WordPressPasskeyAccount( $this->db ) )->gate();
			$permit = array(
				'user_id'     => $own['user_id'],
				'user'        => get_userdata( $own['user_id'] ),
				'fingerprint' => $pending['account_revision'],
			);
			if ( null === $gate->finalCheck( $permit, $now ) ) {
				return false; }
			$verified = ( new PasskeyVerifier() )->registration( $post['payload'], $own['context'], $pending['challenge'] );
			if ( null === $verified || null === $gate->finalCheck( $permit, $now ) ) {
				return false; }
			$fresh = $runtime->own( $post );
			if ( null === $fresh || $fresh['user_id'] !== $own['user_id'] || $fresh['session_hash'] !== $own['session_hash'] || $fresh['context']->fingerprint() !== $pending['context_revision'] || $fresh['policy']['revision'] !== $pending['policy_revision'] ) {
				return false; }
			$handle = ( new PasskeyHandle( $this->db ) )->get( $own['user_id'] );
			if ( null === $handle ) {
				return false; }
			$record = array(
				'version'          => 1,
				'user_id'          => $own['user_id'],
				'credential_id'    => Base64Url::encode( $verified['credential_id'] ),
				'user_handle'      => Base64Url::encode( $handle ),
				'public_key'       => $verified['public_key'],
				'origin'           => $own['context']->origin(),
				'rp_id'            => $own['context']->rpId(),
				'context_revision' => $own['context']->fingerprint(),
				'counter'          => $verified['counter'],
				'backup_eligible'  => $verified['backup_eligible'],
				'backed_up'        => $verified['backed_up'],
				'label'            => sanitize_text_field( $post['label'] ),
				'created_at'       => $now,
				'last_used_at'     => 0,
				'revision'         => bin2hex( random_bytes( 16 ) ),
			);
			$stored = $repository->addCredential( $record, $own['context'], $pending['policy_revision'], $now );
			if ( $stored ) {
				$this->recordChange( $own['user_id'], 'passkey-added' ); }
			return $stored;
		} catch ( \Throwable $error ) {
			return false; }
	}
	public function remove( array $post, int $now ): bool {
		try {
			$runtime = new PasskeyRuntime( $this->db );
			$own     = $runtime->own( $post, false );
			if ( null === $own || ! PasskeyState::hex( $post['credential'] ?? null, 64 ) ) {
				return false; }
			$permit = $this->approve( $post, $own['user_id'], $now );
			if ( null === $permit || null === ( new WordPressPasskeyAccount( $this->db ) )->gate()->finalCheck( $permit, $now ) || null === $runtime->own( $post, false ) ) {
				return false; }
			$removed = ( new PasskeyRepository( $this->db ) )->removeOwn( $post['credential'], $own['user_id'] );
			if ( $removed ) {
				$this->recordChange( $own['user_id'], 'passkey-removed' ); }
			return $removed;
		} catch ( \Throwable $error ) {
			return false; }
	}
	private function recordChange( int $id, string $target ): void {
		( new \AmazingPlugins\Security\Activity\ActivityHooks( new \AmazingPlugins\Security\Activity\ActivityRepository( $this->db ) ) )->record( 'security_setting_changed', $id, $target );
	}

	private function approve( array $post, int $id, int $now ): ?array {
		if ( '1' !== ( $post['confirm'] ?? null ) || ! is_string( $post['password'] ?? null ) || '' === $post['password'] || strlen( $post['password'] ) > 1024 || ! is_string( $post['factor'] ?? null ) || strlen( $post['factor'] ) > 128 ) {
			return null; }
		clean_user_cache( $id );
		$user = get_userdata( $id );
		if ( ! $user instanceof \WP_User || ! wp_check_password( $post['password'], $user->user_pass, $id ) ) {
			return null; }
		return ( new WordPressPasskeyAccount( $this->db ) )->gate()->authorize( $id, $post['factor'], $now );
	}
	private function display( string $text, string $fallback ): string {
		$text = trim( mb_strcut( wp_strip_all_tags( $text ), 0, 64, 'UTF-8' ) );
		return '' !== $text ? $text : $fallback;
	}
	public function beginRequest(): void {
		$this->respond( $this->begin( $this->post(), time() ) ); }
	public function finishRequest(): void {
		$this->respond( $this->finish( $this->post(), time() ) ); }
	public function removeRequest(): void {
		$this->respond( $this->remove( $this->post(), time() ) ); }
	private function post(): array {
	 // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Own-account nonce, exact origin and matched cookies are checked by runtime->own before mutation.
		return wp_unslash( $_POST );
	}
	private function respond( mixed $result ): void {
		nocache_headers();
		if ( false === $result || null === $result ) {
			wp_send_json_error( array( 'message' => __( 'The passkey change could not be saved. Check your password and verification code, reload your profile, and try again.', 'amazing-security' ) ), 403 ); }
		wp_send_json_success( true === $result ? array( 'saved' => true ) : $result );
	}
}
