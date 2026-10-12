<?php

declare(strict_types=1);

namespace {
	if ( ! class_exists( 'WP_Error' ) ) {
		class WP_Error {
			public function __construct( public string $code, public string $message ) {}
		}
	}
	if ( ! function_exists( 'wp_unslash' ) ) {
		function wp_unslash( string $value ): string { return stripslashes( $value ); }
	}
}

namespace AmazingPlugins\Security\Tests\Unit\Login {
	use AmazingPlugins\Security\Login\CommonPasswordHooks;
	use PHPUnit\Framework\TestCase;

	final class CommonPasswordProfileHookTest extends TestCase {
		/** WordPress fires user_profile_update_errors with a plain object, not a WP_User. A typed hook crashes every profile save. */
		public function test_profile_hook_accepts_the_plain_object_core_passes_in(): void {
			$hooks = new CommonPasswordHooks( static fn(): bool => false );
			$error = new \WP_Error( '', '' );
			$user  = new \stdClass();
			$hooks->profile( $error, true, $user );
			self::assertTrue( true );
		}

		public function test_profile_hook_is_a_no_op_when_the_switch_is_off(): void {
			$_POST['pass1'] = 'password';
			$hooks          = new CommonPasswordHooks( static fn(): bool => false, static fn(): bool => true );
			$error          = new \WP_Error( '', '' );
			$hooks->profile( $error, true, new \stdClass() );
			unset( $_POST['pass1'] );
			self::assertSame( '', $error->code );
		}
	}
}
