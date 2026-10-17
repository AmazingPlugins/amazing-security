<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Passkeys;

defined( 'ABSPATH' ) || exit;

// phpcs:disable WordPress.DB.DirectDatabaseQuery -- Bounded plugin-owned tables require fresh reads, atomic claims and guarded admission; all runtime values are prepared.
final class PasskeyRepository {
	private readonly string $pending;
	private readonly string $credentials;
	public function __construct( private readonly object $db ) {
		$this->pending     = $db->prefix . 'amsec_passkey_pending';
		$this->credentials = $db->prefix . 'amsec_passkey_credentials';
	}
	public function currentPolicy(): ?array {
		return $this->quiet( fn(): ?array => ( new PasskeyPolicy() )->read( $this->freshRaw() ), null );
	}
	public function addPending( array $record, PasskeyContext $context, int $now ): bool {
		return $this->quiet(
			function () use ( $record, $context, $now ): bool {
				$raw = $this->encode( $record );
				if ( null === ( new PasskeyPending() )->read( $raw, $now ) || $record['context_revision'] !== $context->fingerprint() ) {
					return false; }
				return $this->locked(
					$this->pending,
					function () use ( $record, $raw, $now ): bool {
						$policyRaw = $this->activeRaw( $record['policy_revision'] );
						if ( null === $policyRaw || ! $this->below( "SELECT COUNT(*) FROM {$this->pending}", 1000 ) || ! $this->below( $this->db->prepare( "SELECT COUNT(*) FROM {$this->pending} WHERE created_at >= %d", $now - 60 ), 100 ) ) {
							return false; }
						$result = $this->db->query( $this->db->prepare( "INSERT INTO {$this->pending} (ticket_hash,user_id,created_at,expires_at,record) SELECT %s,%d,%d,%d,%s FROM {$this->db->options} WHERE option_name=%s AND BINARY option_value=BINARY %s", $record['ticket_hash'], $record['user_id'], $record['created_at'], $record['expires_at'], $raw, PasskeyPolicy::OPTION, $policyRaw ) );
						$this->check();
						return 1 === $result;
					}
				);
			},
			false
		);
	}
	public function claim( string $ticket, string $binding, string $purpose, PasskeyContext $context, int $userId, string $sessionHash, int $now ): ?array {
		if ( strlen( $ticket ) !== 32 || strlen( $binding ) !== 32 ) {
			return null; }
		return $this->quiet(
			function () use ( $ticket, $binding, $purpose, $context, $userId, $sessionHash, $now ): ?array {
				$hash = hash( 'sha256', $ticket );
				$rows = $this->db->get_results( $this->db->prepare( "SELECT ticket_hash,record,claimed_at FROM {$this->pending} WHERE ticket_hash=%s LIMIT 2", $hash ), 'ARRAY_A' );
				$this->check();
				if ( ! is_array( $rows ) || count( $rows ) !== 1 || ( $rows[0]['ticket_hash'] ?? null ) !== $hash || '0' !== (string) ( $rows[0]['claimed_at'] ?? '' ) ) {
					return null; }
				$raw    = $rows[0]['record'] ?? null;
				$record = ( new PasskeyPending() )->read( $raw, $now );
				if ( null === $record || $record['ticket_hash'] !== $hash || ! hash_equals( $record['binding_hash'], hash( 'sha256', $binding ) ) || $record['purpose'] !== $purpose || $record['context_revision'] !== $context->fingerprint() || $record['user_id'] !== $userId || ! hash_equals( $record['session_hash'], $sessionHash ) ) {
					return null; }
				$policyRaw = $this->activeRaw( $record['policy_revision'] );
				if ( null === $policyRaw ) {
					return null; }
				$result = $this->db->query( $this->db->prepare( "UPDATE {$this->pending} p INNER JOIN {$this->db->options} o ON o.option_name=%s AND BINARY option_value=BINARY %s SET p.claimed_at=%d WHERE p.ticket_hash=%s AND p.claimed_at=0 AND BINARY p.record=BINARY %s AND p.expires_at>%d", PasskeyPolicy::OPTION, $policyRaw, $now, $hash, $raw, $now ) );
				$this->check();
				return 1 === $result ? $record : null;
			},
			null
		);
	}
	public function addCredential( array $record, PasskeyContext $context, string $policyRevision, int $now ): bool {
		return $this->quiet(
			function () use ( $record, $context, $policyRevision, $now ): bool {
				$raw = $this->encode( $record );
				if ( null === ( new PasskeyCredential() )->read( $raw, $now ) || $record['context_revision'] !== $context->fingerprint() ) {
					return false; }
				return $this->locked(
					$this->credentials,
					function () use ( $record, $raw, $policyRevision ): bool {
						$policyRaw = $this->activeRaw( $policyRevision );
						if ( null === $policyRaw || ! $this->below( "SELECT COUNT(*) FROM {$this->credentials}", 10000 ) || ! $this->below( $this->db->prepare( "SELECT COUNT(*) FROM {$this->credentials} WHERE user_id=%d", $record['user_id'] ), 5 ) ) {
							return false; }
						$id     = hash( 'sha256', Base64Url::decode( $record['credential_id'], 1024 ) );
						$result = $this->db->query( $this->db->prepare( "INSERT INTO {$this->credentials} (id,user_id,created_at,record) SELECT %s,%d,%d,%s FROM {$this->db->options} WHERE option_name=%s AND BINARY option_value=BINARY %s", $id, $record['user_id'], $record['created_at'], $raw, PasskeyPolicy::OPTION, $policyRaw ) );
						$this->check();
						return 1 === $result;
					}
				);
			},
			false
		);
	}
	public function credential( string $credentialId, int $now ): ?array {
		if ( '' === $credentialId || strlen( $credentialId ) > 1024 ) {
			return null; }
		return $this->quiet(
			function () use ( $credentialId, $now ): ?array {
				$id   = hash( 'sha256', $credentialId );
				$rows = $this->db->get_results( $this->db->prepare( "SELECT id,user_id,record FROM {$this->credentials} WHERE id=%s LIMIT 2", $id ), 'ARRAY_A' );
				$this->check();
				if ( ! is_array( $rows ) || count( $rows ) !== 1 ) {
					return null; }
				$loaded = $this->decodeRow( $rows[0], $now );
				return null !== $loaded && $loaded['id'] === $id ? $loaded : null;
			},
			null
		);
	}
	public function ownCredentials( int $userId, int $now ): ?array {
		if ( $userId < 1 ) {
			return null; }
		return $this->quiet(
			function () use ( $userId, $now ): ?array {
				$rows = $this->db->get_results( $this->db->prepare( "SELECT id,user_id,record FROM {$this->credentials} WHERE user_id=%d ORDER BY created_at ASC LIMIT 6", $userId ), 'ARRAY_A' );
				$this->check();
				if ( ! is_array( $rows ) || count( $rows ) > 5 ) {
					return null; }
				$records = array();
				foreach ( $rows as $row ) {
					$loaded = $this->decodeRow( $row, $now );
					if ( null === $loaded || $loaded['record']['user_id'] !== $userId ) {
						return null; }
					$records[] = $loaded;
				}
				return $records;
			},
			null
		);
	}
	public function consumeCredential( array $loaded, int $counter, bool $backedUp, PasskeyContext $context, string $policyRevision, int $now ): bool {
		return $this->quiet(
			function () use ( $loaded, $counter, $backedUp, $context, $policyRevision, $now ): bool {
				$record = ( new PasskeyCredential() )->read( $loaded['raw'] ?? null, $now );
				if ( null === $record || ( $loaded['record'] ?? null ) !== $record || ( $loaded['id'] ?? null ) !== hash( 'sha256', Base64Url::decode( $record['credential_id'], 1024 ) ) || $record['context_revision'] !== $context->fingerprint() || ! PasskeyState::integer( $counter, 0, 4294967295 ) || ( ( 0 !== $record['counter'] || 0 !== $counter ) && $counter <= $record['counter'] ) || ( $backedUp && ! $record['backup_eligible'] ) ) {
					return false; }
				$policyRaw = $this->activeRaw( $policyRevision );
				if ( null === $policyRaw ) {
					return false; }
				$record['counter']      = $counter;
				$record['backed_up']    = $backedUp;
				$record['last_used_at'] = $now;
				$record['revision']     = bin2hex( random_bytes( 16 ) );
				$newRaw                 = $this->encode( $record );
				if ( null === ( new PasskeyCredential() )->read( $newRaw, $now ) ) {
					return false; }
				$result = $this->db->query( $this->db->prepare( "UPDATE {$this->credentials} c INNER JOIN {$this->db->options} o ON o.option_name=%s AND BINARY option_value=BINARY %s SET c.record=%s WHERE c.id=%s AND c.user_id=%d AND BINARY c.record=BINARY %s", PasskeyPolicy::OPTION, $policyRaw, $newRaw, $loaded['id'], $record['user_id'], $loaded['raw'] ) );
				$this->check();
				return 1 === $result;
			},
			false
		);
	}
	public function removeOwn( string $id, int $userId ): bool {
		if ( ! PasskeyState::hex( $id, 64 ) || $userId < 1 ) {
			return false; }
		return $this->quiet(
			function () use ( $id, $userId ): bool {
				$result = $this->db->query( $this->db->prepare( "DELETE FROM {$this->credentials} WHERE id=%s AND user_id=%d", $id, $userId ) );
				$this->check();
				return 1 === $result;
			},
			false
		);
	}
	private function decodeRow( array $row, int $now ): ?array {
		$record = ( new PasskeyCredential() )->read( $row['record'] ?? null, $now );
		if ( null === $record || (string) ( $row['user_id'] ?? '' ) !== (string) $record['user_id'] || ( $row['id'] ?? null ) !== hash( 'sha256', Base64Url::decode( $record['credential_id'], 1024 ) ) ) {
			return null; }
		return array(
			'id'     => $row['id'],
			'raw'    => $row['record'],
			'record' => $record,
		);
	}
	public function cleanup( int $now ): bool {
		return $this->quiet(
			function () use ( $now ): bool {
				$result = $this->db->query( $this->db->prepare( "DELETE FROM {$this->pending} WHERE expires_at<=%d ORDER BY expires_at ASC LIMIT 100", $now ) );
				$this->check();
				return false !== $result;
			},
			false
		);
	}
	public function revokeUser( int $userId ): bool {
		if ( $userId < 1 ) {
			return false; }
		return $this->quiet(
			function () use ( $userId ): bool {
				$a = $this->db->query( $this->db->prepare( "DELETE FROM {$this->credentials} WHERE user_id=%d", $userId ) );
				$this->check();
				$b = $this->db->query( $this->db->prepare( "DELETE FROM {$this->pending} WHERE user_id=%d", $userId ) );
				$this->check();
				return false !== $a && false !== $b;
			},
			false
		);
	}
	private function activeRaw( string $revision ): ?string {
		$raw    = $this->freshRaw();
		$policy = ( new PasskeyPolicy() )->read( $raw );
		return null !== $policy && $policy['enabled'] && $policy['revision'] === $revision ? $raw : null;
	}
	private function freshRaw(): mixed {
		$raw = $this->db->get_var( $this->db->prepare( "SELECT option_value FROM {$this->db->options} WHERE option_name=%s LIMIT 1", PasskeyPolicy::OPTION ) );
		$this->check();
		return $raw;
	}
	private function below( string $query, int $limit ): bool {
		$count = $this->db->get_var( $query );
		$this->check();
		return ( is_int( $count ) || ( is_string( $count ) && 1 === preg_match( '/^[0-9]+$/D', $count ) ) ) && (int) $count >= 0 && (int) $count < $limit;
	}
	private function locked( string $table, callable $operation ): bool {
		$lock     = 'amsec_pk_' . substr( hash( 'sha256', $table . ( defined( 'DB_NAME' ) ? DB_NAME : '' ) ), 0, 32 );
		$acquired = $this->db->get_var( $this->db->prepare( 'SELECT GET_LOCK(%s,0)', $lock ) );
		$this->check();
		if ( '1' !== (string) $acquired ) {
			return false; }
		try {
			return $operation(); } finally {
					$this->db->get_var( $this->db->prepare( 'SELECT RELEASE_LOCK(%s)', $lock ) ); }
	}
	private function quiet( callable $operation, mixed $failure ): mixed {
		$previous = $this->db->suppress_errors( true );
		try {
			return $operation(); } catch ( \Throwable $error ) {
					return $failure; } finally {
				$this->db->suppress_errors( $previous ); }
	}
	private function check(): void {
		if ( '' !== $this->db->last_error ) {
			throw new \RuntimeException( 'Passkey storage unavailable.' ); }
	}
	private function encode( array $record ): string {
	 // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Exact pure plugin-owned state serialization.
		return json_encode( $record, JSON_THROW_ON_ERROR );
	}
}
// phpcs:enable WordPress.DB.DirectDatabaseQuery
