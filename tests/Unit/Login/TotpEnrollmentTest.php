<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Login;

use AmazingPlugins\Security\Login\PendingEnrollmentStore;
use AmazingPlugins\Security\Login\RecoveryCodes;
use AmazingPlugins\Security\Login\SecretCipher;
use AmazingPlugins\Security\Login\Totp;
use AmazingPlugins\Security\Login\TotpEnrollment;
use AmazingPlugins\Security\Login\TotpStore;
use PHPUnit\Framework\TestCase;

final class TotpEnrollmentTest extends TestCase {
	public function test_https_code_proof_and_one_time_recovery_codes(): void {
		$store = $this->store();
		$pending = new class implements PendingEnrollmentStore {
			public ?string $value = null;
			public function put( int $userId, string $encryptedSeed ): void { $this->value = $encryptedSeed; }
			public function get( int $userId ): ?string { return $this->value; }
			public function clear( int $userId ): void { $this->value = null; }
		};
		$totp = new Totp();
		$enrollment = new TotpEnrollment( $store, $pending, new SecretCipher( str_repeat( 's', 64 ) ), $totp, new RecoveryCodes() );
		self::assertFalse( $enrollment->begin( 7, false )->allowed );
		$start = $enrollment->begin( 7, true );
		self::assertTrue( $start->allowed );
		self::assertNotEmpty( $start->secretBase32 );
		self::assertSame( array(), $enrollment->confirm( 7, '000000' ) );
		$seed = ( new SecretCipher( str_repeat( 's', 64 ) ) )->decrypt( $pending->value );
		$codes = $enrollment->confirm( 7, $totp->atStep( $seed, intdiv( time(), 30 ) ) );
		self::assertCount( 10, $codes );
		self::assertNull( $pending->value );
		self::assertSame( array(), $enrollment->confirm( 7, '000000' ) );
		self::assertFalse( str_contains( serialize( $store->saved ), $codes[0] ) );
	}

	private function store(): TotpStore {
		return new class implements TotpStore {
			public array $saved = array();
			public function enroll( int $userId, string $encryptedSecret, array $recoveryHashes ): bool { $this->saved = array( 'secret' => $encryptedSecret, 'hashes' => $recoveryHashes, 'last' => -1 ); return true; }
			public function isEnrolled( int $userId ): bool { return array() !== $this->saved; }
			public function encryptedSecret( int $userId ): ?string { return $this->saved['secret'] ?? null; }
			public function lastStep( int $userId ): ?int { return $this->saved['last'] ?? null; }
			public function consumeStep( int $userId, int $step ): bool { if ( $step <= $this->saved['last'] ) { return false; } $this->saved['last'] = $step; return true; }
			public function consumeRecoveryCode( int $userId, string $code ): bool { return false; }
			public function replaceRecoveryCodes( int $userId, array $hashes ): bool { return true; }
			public function disable( int $userId ): bool { $this->saved = array(); return true; }
		};
	}
}
