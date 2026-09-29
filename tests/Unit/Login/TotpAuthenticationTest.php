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

		public function test_api_scope_excludes_rest_and_cli(): void {
			self::assertTrue( TotpAuthentication::isApiRequest( true, false ) );
			self::assertTrue( TotpAuthentication::isApiRequest( false, true ) );
			self::assertFalse( TotpAuthentication::isApiRequest( false, false ) );
		}

		private function store( string $encrypted ): TotpStore {
			return new class( $encrypted ) implements TotpStore {
				public int $last = -1;
				public function __construct( private string $encrypted ) {}
				public function enroll( int $userId, string $encryptedSecret, array $recoveryHashes ): bool { return false; }
				public function isEnrolled( int $userId ): bool { return 7 === $userId; }
				public function encryptedSecret( int $userId ): ?string { return $this->encrypted; }
				public function lastStep( int $userId ): ?int { return $this->last; }
				public function consumeStep( int $userId, int $step ): bool { if ( $step <= $this->last ) { return false; } $this->last = $step; return true; }
				public function consumeRecoveryCode( int $userId, string $code ): bool { return false; }
				public function replaceRecoveryCodes( int $userId, array $hashes ): bool { return false; }
				public function disable( int $userId ): bool { return false; }
			};
		}
	}
}
