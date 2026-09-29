<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Login;

use RuntimeException;

final class TotpAuthentication {
	public function __construct( private TotpStore $store, private SecretCipher $cipher, private Totp $totp ) {}

	public static function isApiRequest( bool $rest, bool $cli ): bool {
		return $rest || $cli;
	}

	public function authenticate( mixed $user, string $username, string $password ): mixed {
		if ( '' === $username || '' === $password || ! $user instanceof \WP_User || ! user_can( $user, 'manage_options' ) || self::isApiRequest( defined( 'REST_REQUEST' ) && REST_REQUEST, defined( 'WP_CLI' ) && WP_CLI ) ) {
			return $user;
		}
		try {
			if ( ! $this->store->isEnrolled( $user->ID ) ) {
				return $user;
			}
			// Login forms use WordPress authentication instead of a plugin admin nonce.
			// phpcs:ignore WordPress.Security.NonceVerification.Missing
			$factor    = isset( $_POST['amsec_otp'] ) && is_string( $_POST['amsec_otp'] ) ? sanitize_text_field( wp_unslash( $_POST['amsec_otp'] ) ) : '';
			$encrypted = $this->store->encryptedSecret( $user->ID );
			$seed      = null === $encrypted ? null : $this->cipher->decrypt( $encrypted );
			if ( null !== $seed ) {
				$step = $this->totp->verify( $seed, $factor, time(), $this->store->lastStep( $user->ID ) );
				if ( null !== $step && $this->store->consumeStep( $user->ID, $step ) ) {
					return $user;
				}
			}
			if ( $this->store->consumeRecoveryCode( $user->ID, $factor ) ) {
				return $user;
			}
		} catch ( RuntimeException ) {
			return new \WP_Error( 'amsec_verification_failed', __( 'Verification could not be completed.', 'amazing-security' ) );
		}
		return new \WP_Error( 'amsec_verification_failed', __( 'Verification could not be completed.', 'amazing-security' ) );
	}
}
