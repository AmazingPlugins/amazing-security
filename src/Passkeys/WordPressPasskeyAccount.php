<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Passkeys;

use AmazingPlugins\Security\Login\{RequiredTotpPolicy, RequiredTotpState, SecretCipher, Totp, TotpAuthentication, WordPressTotpStore};
use AmazingPlugins\Security\Incident\ResetRequirement;

// phpcs:disable WordPress.DB.DirectDatabaseQuery -- Authentication must read account restrictions freshly and guard grace enrollment against changed policy/metadata.
final class WordPressPasskeyAccount {
	public function __construct( private readonly object $db ) {}
	public function factor(): TotpAuthentication {
		return new TotpAuthentication( new WordPressTotpStore( $this->db ), new SecretCipher( wp_salt( 'auth' ) ), new Totp() );
	}
	public function gate( bool $consumeFactor = true ): PasskeyAccountGate {
		return new PasskeyAccountGate(
			fn( int $id, int $now ): ?array => $this->state( $id, $now ),
			fn( int $id, string $factor, int $now ): bool => $consumeFactor ? $this->factor()->verifyFactor( $id, $factor, $now ) : $this->factor()->matchesFactor( $id, $factor, $now ),
			fn( int $id, string $revision, int $now ): bool => $this->grantGrace( $id, $revision, $now ),
			static function ( \WP_User $user ): mixed {
				$id   = $user->ID;
				$user = apply_filters( 'wp_authenticate_user', $user, '' ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Re-run the core account filter before a passkey is accepted.
				if ( ! $user instanceof \WP_User || $user->ID !== $id ) {
					return null; }
				return apply_filters( 'authenticate', $user, '', '' ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Re-run the core authentication filter before a passkey is accepted.
			}
		);
	}
	public function state( int $id, int $now ): ?array {
		if ( $id < 1 || $now < 0 ) {
			return null; }
		return $this->quiet(
			function () use ( $id, $now ): ?array {
				clean_user_cache( $id );
				$user = get_userdata( $id );
				if ( ! $user instanceof \WP_User || $user->ID !== $id ) {
					return null; }
				$admin = user_can( $user, 'manage_options' );
				$reset = $this->meta( $id, ResetRequirement::KEY, 8 );
				if ( null !== $reset && '1' !== $reset ) {
					throw new \RuntimeException( 'Account restriction unavailable.' ); }
				$generation     = $this->generation();
				$store          = new WordPressTotpStore( $this->db );
				$enrolled       = $admin && $store->isEnrolled( $id );
				$factorRevision = '';
				if ( $enrolled ) {
					$encrypted = $store->encryptedSecret( $id );
					if ( null === $encrypted ) {
						throw new \RuntimeException( 'Factor unavailable.' ); }
					$factorRevision = hash( 'sha256', $encrypted );
				}
				$grace           = $admin && '' !== $generation && ! $enrolled ? $this->meta( $id, RequiredTotpPolicy::META, 2048 ) : null;
				$required        = ! $admin || '' === $generation ? 'off' : ( $enrolled ? 'enrolled' : RequiredTotpState::evaluate( $this->graceValue( $grace ), $generation, $now ) );
				$accountRevision = $this->fingerprint( array( $id, $user->user_login, $user->user_pass, $user->user_email, $user->roles, $user->allcaps, $admin, $enrolled, $factorRevision, $reset ) );
				return array(
					'user'             => $user,
					'admin'            => $admin,
					'enrolled'         => $enrolled,
					'required'         => $required,
					'reset_required'   => '1' === $reset,
					'policy_revision'  => $generation,
					'account_revision' => $accountRevision,
					'fingerprint'      => $this->fingerprint( array( $accountRevision, $generation, $grace, $required ) ),
				);
			}
		);
	}
	private function grantGrace( int $id, string $revision, int $now ): bool {
		if ( ! PasskeyState::hex( $revision, 32 ) || $now < 1 || $now > PHP_INT_MAX - RequiredTotpPolicy::GRACE ) {
			return false; }
		return true === $this->quiet(
			function () use ( $id, $revision, $now ): bool {
				$lock = 'amsec_pkg_' . substr( hash( 'sha256', $this->db->usermeta . ':' . $id . ( defined( 'DB_NAME' ) ? DB_NAME : '' ) ), 0, 32 );
				$got  = $this->db->get_var( $this->db->prepare( 'SELECT GET_LOCK(%s,0)', $lock ) );
				$this->check();
				if ( '1' !== (string) $got ) {
					return false; }
				try {
					$state = $this->state( $id, $now );
					if ( null === $state || ! $state['admin'] || $state['enrolled'] || $state['reset_required'] || $state['policy_revision'] !== $revision || 'new' !== $state['required'] ) {
						return false; }
					$old = $this->meta( $id, RequiredTotpPolicy::META, 2048 );
                   // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.serialize_serialize -- Match the existing required-enrollment WordPress user-meta array representation for exact CAS.
					$value = serialize(
						array(
							'generation' => $revision,
							'deadline'   => $now + RequiredTotpPolicy::GRACE,
						)
					);
					if ( null === $old ) {
								$result = $this->db->query( $this->db->prepare( "INSERT INTO {$this->db->usermeta} (user_id,meta_key,meta_value) SELECT %d,%s,%s FROM {$this->db->options} WHERE option_name=%s AND BINARY option_value=BINARY %s AND NOT EXISTS (SELECT 1 FROM {$this->db->usermeta} WHERE user_id=%d AND meta_key=%s)", $id, RequiredTotpPolicy::META, $value, RequiredTotpPolicy::OPTION, $revision, $id, RequiredTotpPolicy::META ) );
					} else {
						$result = $this->db->query( $this->db->prepare( "UPDATE {$this->db->usermeta} m INNER JOIN {$this->db->options} o ON o.option_name=%s AND BINARY o.option_value=BINARY %s SET m.meta_value=%s WHERE m.user_id=%d AND m.meta_key=%s AND BINARY m.meta_value=BINARY %s", RequiredTotpPolicy::OPTION, $revision, $value, $id, RequiredTotpPolicy::META, $old ) );
					}
					$this->check();
					wp_cache_delete( $id, 'user_meta' );
					return 1 === $result && $this->meta( $id, RequiredTotpPolicy::META, 2048 ) === $value && $this->generation() === $revision;
				} finally {
					$this->db->get_var( $this->db->prepare( 'SELECT RELEASE_LOCK(%s)', $lock ) ); }
			}
		);
	}
	private function generation(): string {
		$raw = $this->db->get_var( $this->db->prepare( "SELECT option_value FROM {$this->db->options} WHERE option_name=%s LIMIT 1", RequiredTotpPolicy::OPTION ) );
		$this->check();
		if ( null === $raw || '' === $raw ) {
			return ''; }
		if ( ! PasskeyState::hex( $raw, 32 ) ) {
			throw new \RuntimeException( 'Required enrollment policy unavailable.' ); }
		return $raw;
	}
	private function meta( int $id, string $key, int $limit ): ?string {
		$rows = $this->db->get_results( $this->db->prepare( "SELECT meta_value FROM {$this->db->usermeta} WHERE user_id=%d AND meta_key=%s LIMIT 2", $id, $key ), 'ARRAY_A' );
		$this->check();
		if ( ! is_array( $rows ) || count( $rows ) > 1 ) {
			throw new \RuntimeException( 'Account metadata unavailable.' ); }
		if ( array() === $rows ) {
			return null; }
		$raw = $rows[0]['meta_value'] ?? null;
		if ( ! is_string( $raw ) || strlen( $raw ) > $limit ) {
			throw new \RuntimeException( 'Account metadata unavailable.' ); }
		return $raw;
	}
	private function graceValue( ?string $raw ): mixed {
		if ( null === $raw ) {
			return ''; }
		if ( ! str_starts_with( $raw, 'a:' ) ) {
			return null; }
	 // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.serialize_unserialize,WordPress.PHP.NoSilencedErrors.Discouraged -- Bounded existing WP metadata array only; object creation disabled, exact shape validated below.
		$value = @unserialize( $raw, array( 'allowed_classes' => false ) );
		return is_array( $value ) && array_keys( $value ) === array( 'generation', 'deadline' ) ? $value : null;
	}
	private function fingerprint( array $values ): string {
	 // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- In-memory authentication snapshot hash; never persisted or logged.
		return hash( 'sha256', json_encode( $values, JSON_THROW_ON_ERROR ) );
	}
	private function quiet( callable $operation ): mixed {
		$old = $this->db->suppress_errors( true );
		try {
			return $operation(); } catch ( \Throwable $error ) {
					return null; } finally {
				$this->db->suppress_errors( $old ); }
	}
	private function check(): void {
		if ( '' !== $this->db->last_error ) {
			throw new \RuntimeException( 'Account policy storage unavailable.' ); }
	}
}
// phpcs:enable WordPress.DB.DirectDatabaseQuery
