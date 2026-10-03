<?php

declare(strict_types=1);

namespace {
	if ( ! class_exists( 'WP_User' ) ) {
		class WP_User {
			public function __construct( public int $ID, public bool $admin = true ) {}
		}
	}
	if ( ! class_exists( 'WP_Error' ) ) {
		class WP_Error {
			public function __construct( public string $code, public string $message ) {}
		}
	}
	if ( ! function_exists( 'user_can' ) ) {
		function user_can( WP_User $user, string $capability ): bool { return $user->admin; }
	}
	if ( ! function_exists( '__' ) ) {
		function __( string $text, string $domain ): string { return $text; }
	}
	if ( ! function_exists( 'wp_unslash' ) ) {
		function wp_unslash( string $value ): string { return stripslashes( $value ); }
	}
	if ( ! function_exists( 'sanitize_text_field' ) ) {
		function sanitize_text_field( string $value ): string { return strip_tags( $value ); }
	}
}

namespace AmazingPlugins\Security\Tests\Unit\Login {
	use AmazingPlugins\Security\Login\SecretCipher;
	use AmazingPlugins\Security\Login\Totp;
	use AmazingPlugins\Security\Login\TotpAuthentication;
	use AmazingPlugins\Security\Login\TotpStore;
	use PHPUnit\Framework\TestCase;

	final class TotpAuthenticationTest extends TestCase {
		public function test_enrolled_admin_needs_one_time_factor_after_password(): void {
			$seed = '12345678901234567890';
			$cipher = new SecretCipher( str_repeat( 's', 64 ) );
			$store = $this->store( $cipher->encrypt( $seed ) );
			$auth = new TotpAuthentication( $store, $cipher, new Totp() );
			$admin = new \WP_User( 7 );
			$wrongPassword = new \WP_Error( 'incorrect_password', 'Wrong password' );
			self::assertSame( $wrongPassword, $auth->authenticate( $wrongPassword, 'owner', 'wrong' ) );
			$_POST = array();
			self::assertInstanceOf( \WP_Error::class, $auth->authenticate( $admin, 'owner', 'correct' ) );
			$_POST['amsec_otp'] = ( new Totp() )->atStep( $seed, intdiv( time(), 30 ) );
			self::assertSame( $admin, $auth->authenticate( $admin, 'owner', 'correct' ) );
			self::assertInstanceOf( \WP_Error::class, $auth->authenticate( $admin, 'owner', 'correct' ) );
			$customer = new \WP_User( 8, false );
			self::assertSame( $customer, $auth->authenticate( $customer, 'customer', 'correct' ) );
			$_POST = array();
		}

		public function test_matching_a_factor_does_not_spend_it(): void {
			$seed = random_bytes( 20 );
			$cipher = new SecretCipher( str_repeat( 's', 64 ) );
			$store = $this->store( $cipher->encrypt( $seed ) );
			$auth = new TotpAuthentication( $store, $cipher, new Totp() );
			$now = 1800000000;
			$code = ( new Totp() )->atStep( $seed, intdiv( $now, 30 ) );
			self::assertTrue( $auth->matchesFactor( 7, $code, $now ) );
			self::assertSame( -1, $store->last );
			self::assertTrue( $auth->verifyFactor( 7, $code, $now ) );
			$store->recovery = bin2hex( random_bytes( 12 ) );
			self::assertTrue( $auth->matchesFactor( 7, $store->recovery, $now ) );
			self::assertNotSame( '', $store->recovery );
		}

		public function test_api_scope_excludes_rest_cli_and_xml_rpc(): void {
			self::assertTrue( TotpAuthentication::isApiRequest( true, false, false ) );
			self::assertTrue( TotpAuthentication::isApiRequest( false, true, false ) );
			self::assertTrue( TotpAuthentication::isApiRequest( false, false, true ) );
			self::assertFalse( TotpAuthentication::isApiRequest( false, false, false ) );
		}

		public function test_shared_factor_verification_preserves_one_use_steps_recovery_and_failures(): void {
			$seed = random_bytes(20);$cipher = new SecretCipher(str_repeat('s',64));$store = $this->store($cipher->encrypt($seed));$auth = new TotpAuthentication($store,$cipher,new Totp());$now = 1800000000;
			self::assertFalse($auth->verifyFactor(8,'123456',$now));self::assertFalse($auth->verifyFactor(7,'wrong',$now));$code = (new Totp())->atStep($seed,intdiv($now,30));self::assertTrue($auth->verifyFactor(7,$code,$now));self::assertFalse($auth->verifyFactor(7,$code,$now));
			$store->recovery = bin2hex(random_bytes(12));$recovery = $store->recovery;self::assertTrue($auth->verifyFactor(7,$recovery,$now));self::assertFalse($auth->verifyFactor(7,$recovery,$now));self::assertFalse($auth->verifyFactor(7,str_repeat('x',129),$now));$store->broken = true;self::assertFalse($auth->verifyFactor(7,$code,$now));
		}

		private function store( string $encrypted ): TotpStore {
			return new class( $encrypted ) implements TotpStore {
				public int $last = -1;
				public string $recovery = '';
				public bool $broken = false;
				public function __construct( private string $encrypted ) {}
				public function enroll( int $userId, string $encryptedSecret, array $recoveryHashes ): bool { return false; }
				public function isEnrolled( int $userId ): bool { if($this->broken)throw new \RuntimeException('Unavailable');return 7 === $userId; }
				public function encryptedSecret( int $userId ): ?string { return $this->encrypted; }
				public function lastStep( int $userId ): ?int { return $this->last; }
				public function consumeStep( int $userId, int $step ): bool { if ( $step <= $this->last ) { return false; } $this->last = $step; return true; }
				public function consumeRecoveryCode( int $userId, string $code ): bool { if($this->recovery!==''&&$code===$this->recovery){$this->recovery='';return true;}return false; }
				public function hasRecoveryCode( int $userId, string $code ): bool { return $this->recovery !== '' && $code === $this->recovery; }
				public function replaceRecoveryCodes( int $userId, array $hashes ): bool { return false; }
				public function disable( int $userId ): bool { return false; }
			};
		}
	}
}
