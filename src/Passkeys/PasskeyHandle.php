<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Passkeys;

// phpcs:disable WordPress.DB.DirectDatabaseQuery -- Fresh uniqueness reads and zero-wait admission for a feature-owned opaque account handle; values are prepared.
final class PasskeyHandle {
	public const META = 'amsec_passkey_handle';
	public function __construct( private readonly object $db ) {}
	/** Creation is called only after fresh own-account password/factor approval. */
	public function get( int $userId, bool $create = false ): ?string {
		if ( $userId < 1 ) {
			return null; }
		$previous = $this->db->suppress_errors( true );
		try {
			$existing = $this->fresh( $userId );
			if ( null !== $existing || ! $create ) {
				return $existing; }
			$lock     = 'amsec_pkh_' . substr( hash( 'sha256', $this->db->usermeta . ( defined( 'DB_NAME' ) ? DB_NAME : '' ) ), 0, 32 );
			$acquired = $this->db->get_var( $this->db->prepare( 'SELECT GET_LOCK(%s,0)', $lock ) );
			$this->check();
			if ( '1' !== (string) $acquired ) {
				return null; }
			try {
				$existing = $this->fresh( $userId );
				if ( null !== $existing ) {
					return $existing; }
				$count = $this->db->get_var( $this->db->prepare( "SELECT COUNT(*) FROM {$this->db->usermeta} WHERE meta_key=%s", self::META ) );
				$this->check();
				if ( ! ( is_int( $count ) || ( is_string( $count ) && 1 === preg_match( '/^[0-9]+$/D', $count ) ) ) || (int) $count < 0 || (int) $count >= 10000 ) {
					return null; }
				$handle  = random_bytes( 32 );
				$encoded = Base64Url::encode( $handle );
				$result  = $this->db->query( $this->db->prepare( "INSERT INTO {$this->db->usermeta} (user_id,meta_value,meta_key) SELECT %d,%s,%s FROM {$this->db->users} WHERE ID=%d AND NOT EXISTS (SELECT 1 FROM {$this->db->usermeta} WHERE user_id=%d AND meta_key=%s) AND NOT EXISTS (SELECT 1 FROM {$this->db->usermeta} WHERE meta_key=%s AND BINARY meta_value=BINARY %s)", $userId, $encoded, self::META, $userId, $userId, self::META, self::META, $encoded ) );
				$this->check();
				if ( 1 !== $result ) {
					return null; }
				$fresh = $this->fresh( $userId );
				return null !== $fresh && hash_equals( $handle, $fresh ) ? $handle : null;
			} finally {
				$this->db->get_var( $this->db->prepare( 'SELECT RELEASE_LOCK(%s)', $lock ) ); }
		} catch ( \Throwable $error ) {
			return null; } finally {
					$this->db->suppress_errors( $previous ); }
	}
	private function fresh( int $userId ): ?string {
		$rows = $this->db->get_results( $this->db->prepare( "SELECT meta_value FROM {$this->db->usermeta} WHERE user_id=%d AND meta_key=%s LIMIT 2", $userId, self::META ), 'ARRAY_A' );
		$this->check();
		if ( ! is_array( $rows ) || count( $rows ) > 1 ) {
			throw new \RuntimeException( 'Passkey account handle unavailable.' ); }
		if ( array() === $rows ) {
			return null; }
		$value = Base64Url::decode( $rows[0]['meta_value'] ?? null, 32 );
		if ( null === $value || strlen( $value ) !== 32 ) {
			throw new \RuntimeException( 'Passkey account handle unavailable.' ); }
		return $value;
	}
	private function check(): void {
		if ( '' !== $this->db->last_error ) {
			throw new \RuntimeException( 'Passkey account handle unavailable.' ); }
	}
}
// phpcs:enable WordPress.DB.DirectDatabaseQuery
