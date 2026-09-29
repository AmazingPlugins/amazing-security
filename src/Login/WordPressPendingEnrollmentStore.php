<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Login;

final class WordPressPendingEnrollmentStore implements PendingEnrollmentStore {
	public function put( int $userId, string $encryptedSeed ): void {
		set_transient( $this->key( $userId ), $encryptedSeed, 5 * MINUTE_IN_SECONDS );
	}

	public function get( int $userId ): ?string {
		$value = get_transient( $this->key( $userId ) );
		return is_string( $value ) ? $value : null;
	}

	public function clear( int $userId ): void {
		delete_transient( $this->key( $userId ) );
	}

	private function key( int $userId ): string {
		$session = wp_get_session_token();
		return 'amsec_totp_pending_' . hash_hmac( 'sha256', (string) $userId . ':' . $session, wp_salt( 'auth' ) );
	}
}
