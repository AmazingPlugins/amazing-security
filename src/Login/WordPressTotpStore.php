<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Login;

use RuntimeException;

final class WordPressTotpStore implements TotpStore {
	private const KEY = 'amsec_totp_v1';

	public function __construct( private object $db ) {}

	public function enroll( int $userId, string $encryptedSecret, array $recoveryHashes ): bool {
		if ( $userId < 1 || $this->isEnrolled( $userId ) || ! $this->validHashes( $recoveryHashes ) ) {
			return false;
		}
		$value = wp_json_encode(
			array(
				'secret'    => $encryptedSecret,
				'last_step' => -1,
				'recovery'  => array_values( $recoveryHashes ),
			)
		);
		return is_string( $value ) && false !== add_user_meta( $userId, self::KEY, $value, true );
	}

	public function isEnrolled( int $userId ): bool {
		return null !== $this->rawRows( $userId );
	}

	public function encryptedSecret( int $userId ): ?string {
		$record = $this->record( $userId );
		return $record['secret'] ?? null;
	}

	public function lastStep( int $userId ): ?int {
		$record = $this->record( $userId );
		return isset( $record['last_step'] ) ? (int) $record['last_step'] : null;
	}

	public function consumeStep( int $userId, int $step ): bool {
		if ( $step < 0 ) {
			return false;
		}
		return $this->change(
			$userId,
			static function ( array $record ) use ( $step ): ?array {
				if ( $step <= $record['last_step'] ) {
					return null;
				}
				$record['last_step'] = $step;
				return $record;
			}
		);
	}

	public function hasRecoveryCode( int $userId, string $code ): bool {
		if ( ! preg_match( '/\A[a-f0-9]{24}\z/', $code ) ) {
			return false;
		}
		$record = $this->record( $userId );
		if ( null === $record ) {
			return false;
		}
		foreach ( $record['recovery'] as $hash ) {
			if ( is_string( $hash ) && password_verify( $code, $hash ) ) {
				return true;
			}
		}
		return false;
	}

	public function consumeRecoveryCode( int $userId, string $code ): bool {
		if ( ! preg_match( '/\A[a-f0-9]{24}\z/', $code ) ) {
			return false;
		}
		return $this->change(
			$userId,
			static function ( array $record ) use ( $code ): ?array {
				foreach ( $record['recovery'] as $index => $hash ) {
					if ( password_verify( $code, $hash ) ) {
						unset( $record['recovery'][ $index ] );
						$record['recovery'] = array_values( $record['recovery'] );
						return $record;
					}
				}
				return null;
			}
		);
	}

	public function replaceRecoveryCodes( int $userId, array $hashes ): bool {
		if ( ! $this->validHashes( $hashes ) ) {
			return false;
		}
		return $this->change(
			$userId,
			static function ( array $record ) use ( $hashes ): array {
				$record['recovery'] = array_values( $hashes );
				return $record;
			}
		);
	}

	public function disable( int $userId ): bool {
		return ! $this->isEnrolled( $userId ) || delete_user_meta( $userId, self::KEY );
	}

	private function change( int $userId, callable $mutation ): bool {
		$rows = $this->rawRows( $userId );
		if ( null === $rows || 1 !== count( $rows ) ) {
			return false;
		}
		$old    = $rows[0]['meta_value'];
		$record = json_decode( $old, true );
		if ( ! $this->validRecord( $record ) ) {
			return false;
		}
		$next = $mutation( $record );
		if ( null === $next ) {
			return false;
		}
		$new = wp_json_encode( $next );
		if ( ! is_string( $new ) ) {
			return false;
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Compare-and-swap makes recovery codes and TOTP steps single-use.
		$updated = $this->db->query( $this->db->prepare( "UPDATE {$this->db->usermeta} SET meta_value = %s WHERE umeta_id = %d AND BINARY meta_value = BINARY %s", $new, (int) $rows[0]['umeta_id'], $old ) );
		if ( 1 !== $updated ) {
			return false;
		}
		wp_cache_delete( $userId, 'user_meta' );
		return true;
	}

	private function record( int $userId ): ?array {
		$rows = $this->rawRows( $userId );
		if ( null === $rows || 1 !== count( $rows ) ) {
			return null;
		}
		$record = json_decode( $rows[0]['meta_value'], true );
		return $this->validRecord( $record ) ? $record : null;
	}

	private function rawRows( int $userId ): ?array {
		if ( $userId < 1 ) {
			return null;
		}
		// The user_id index bounds this lookup to one account; raw rows detect duplicates for atomic writes.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.SlowDBQuery.slow_db_query_meta_key
		$rows = $this->db->get_results( $this->db->prepare( "SELECT umeta_id, meta_value FROM {$this->db->usermeta} WHERE user_id = %d AND meta_key = %s LIMIT 2", $userId, self::KEY ), 'ARRAY_A' );
		if ( ! is_array( $rows ) || ( isset( $this->db->last_error ) && '' !== $this->db->last_error ) ) {
			throw new RuntimeException( 'TOTP enrollment state is unavailable.' );
		}
		return is_array( $rows ) && array() !== $rows ? $rows : null;
	}

	private function validRecord( mixed $record ): bool {
		return is_array( $record ) && isset( $record['secret'], $record['last_step'], $record['recovery'] ) && is_string( $record['secret'] ) && is_int( $record['last_step'] ) && is_array( $record['recovery'] ) && $this->validHashes( $record['recovery'] );
	}

	private function validHashes( array $hashes ): bool {
		if ( count( $hashes ) > 10 ) {
			return false;
		}
		foreach ( $hashes as $hash ) {
			if ( ! is_string( $hash ) || strlen( $hash ) > 255 || '' === $hash ) {
				return false;
			}
		}
		return true;
	}
}
