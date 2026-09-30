<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Login;

use RuntimeException;

final class TotpAuthentication {
	public function __construct( private TotpStore $store, private SecretCipher $cipher, private Totp $totp ) {}

	public static function isApiRequest( bool $rest, bool $cli, bool $xmlRpc ): bool {
		return $rest || $cli || $xmlRpc;
	}

	public function authenticate( mixed $user, string $username, string $password ): mixed {
		if ( '' === $username || '' === $password || ! $user instanceof \WP_User || ! user_can( $user, 'manage_options' ) || self::isApiRequest( defined( 'REST_REQUEST' ) && REST_REQUEST, defined( 'WP_CLI' ) && WP_CLI, defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) ) {
			return $user;
		}
		try {
			if ( ! $this->store->isEnrolled( $user->ID ) ) {
				return $user;
			}
			// Login forms use WordPress authentication instead of a plugin admin nonce.
			// phpcs:ignore WordPress.Security.NonceVerification.Missing
			$factor = isset( $_POST['amsec_otp'] ) && is_string( $_POST['amsec_otp'] ) ? sanitize_text_field( wp_unslash( $_POST['amsec_otp'] ) ) : '';
			if ( $this->verifyFactor( $user->ID, $factor, time() ) ) {
				return $user;
			}
		} catch ( RuntimeException ) {
			return new \WP_Error( 'amsec_verification_failed', __( 'Verification could not be completed.', 'amazing-security' ) );
		}
		return new \WP_Error( 'amsec_verification_failed', __( 'Verification could not be completed.', 'amazing-security' ) );
	}
	/** Shared one-use verification for password and passkey flows. */
	public function verifyFactor( int $userId, string $factor, int $now ): bool {
		if ( $userId < 1 || $now < 0 || strlen( $factor ) > 128 ) {
			return false;
		}
		try {
			if ( ! $this->store->isEnrolled( $userId ) ) {
				return false;
			}
			$encrypted = $this->store->encryptedSecret( $userId );
			$seed      = null === $encrypted ? null : $this->cipher->decrypt( $encrypted );
			if ( null !== $seed ) {
				$step = $this->totp->verify( $seed, $factor, $now, $this->store->lastStep( $userId ) );
				if ( null !== $step && $this->store->consumeStep( $userId, $step ) ) {
					return true;
				}
			}
			return $this->store->consumeRecoveryCode( $userId, $factor );
		} catch ( RuntimeException ) {
			return false;
		}
	}
}
