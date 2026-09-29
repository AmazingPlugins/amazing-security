<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Login;

use RuntimeException;

final class TotpEnrollment {
	public function __construct(
		private TotpStore $store,
		private PendingEnrollmentStore $pending,
		private SecretCipher $cipher,
		private Totp $totp,
		private RecoveryCodes $recovery
	) {}

	public function begin( int $userId, bool $https ): EnrollmentResult {
		if ( ! $https || $userId < 1 || $this->store->isEnrolled( $userId ) ) {
			return new EnrollmentResult( false );
		}
		try {
			$seed = $this->totp->generateSecret();
			$this->pending->put( $userId, $this->cipher->encrypt( $seed ) );
			return new EnrollmentResult( true, $this->totp->base32( $seed ) );
		} catch ( RuntimeException ) {
			return new EnrollmentResult( false );
		}
	}

	public function confirm( int $userId, string $code ): array {
		$encrypted = $this->pending->get( $userId );
		$seed      = null === $encrypted ? null : $this->cipher->decrypt( $encrypted );
		if ( null === $seed || null === $this->totp->verify( $seed, $code, time(), null ) || $this->store->isEnrolled( $userId ) ) {
			return array();
		}
		$codes = $this->recovery->generate();
		if ( ! $this->store->enroll( $userId, $encrypted, $this->recovery->hashAll( $codes ) ) ) {
			return array();
		}
		$this->pending->clear( $userId );
		return $codes;
	}

	public function verifyFactor( int $userId, string $factor ): bool {
		$encrypted = $this->store->encryptedSecret( $userId );
		$seed      = null === $encrypted ? null : $this->cipher->decrypt( $encrypted );
		if ( null !== $seed ) {
			$step = $this->totp->verify( $seed, $factor, time(), $this->store->lastStep( $userId ) );
			if ( null !== $step && $this->store->consumeStep( $userId, $step ) ) {
				return true;
			}
		}
		return $this->store->consumeRecoveryCode( $userId, $factor );
	}

	public function disable( int $userId, string $currentFactor ): bool {
		return $this->verifyFactor( $userId, $currentFactor ) && $this->store->disable( $userId );
	}

	public function regenerate( int $userId, string $currentFactor ): array {
		if ( ! $this->verifyFactor( $userId, $currentFactor ) ) {
			return array();
		}
		$codes = $this->recovery->generate();
		return $this->store->replaceRecoveryCodes( $userId, $this->recovery->hashAll( $codes ) ) ? $codes : array();
	}
}
