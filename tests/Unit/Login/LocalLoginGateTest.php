<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Login;

use AmazingPlugins\Security\Admin\StartHere;
use AmazingPlugins\Security\Checks\GapCheck;
use AmazingPlugins\Security\Login\CommonPasswords;
use AmazingPlugins\Security\Login\LoginConfirmation;
use AmazingPlugins\Security\Login\LoginHints;
use AmazingPlugins\Security\Scan\ScanContext;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class LocalLoginGateTest extends TestCase {
	public function test_common_passwords_match_only_the_local_list(): void {
		self::assertTrue( CommonPasswords::matches( 'password' ) );
		self::assertTrue( CommonPasswords::matches( '123456' ) );
		self::assertFalse( CommonPasswords::matches( '' ) );
		self::assertFalse( CommonPasswords::matches( 'a-long-unique-fixture-password' ) );
	}

	public function test_confirmation_stays_on_the_wordpress_login_form(): void {
		self::assertSame( 'allow', LoginConfirmation::decision( false, array( 'log' => 'a', 'pwd' => 'secret' ), false, false ) );
		self::assertSame( 'allow', LoginConfirmation::decision( true, array( 'username' => 'a', 'password' => 'secret' ), false, false ) );
		self::assertSame( 'allow', LoginConfirmation::decision( true, array( 'log' => 'a', 'pwd' => 'secret' ), true, false ) );
		self::assertSame( 'allow', LoginConfirmation::decision( true, array( 'log' => 'a', 'pwd' => 'secret' ), false, true ) );
		// Nothing to tick: an untouched form, or one without the field, signs in. Only a filled hidden field is refused.
		self::assertSame( 'allow', LoginConfirmation::decision( true, array( 'log' => 'a', 'pwd' => 'secret' ), false, false ) );
		self::assertSame( 'allow', LoginConfirmation::decision( true, array( 'log' => 'a', 'pwd' => 'secret', LoginConfirmation::FIELD => '' ), false, false ) );
		self::assertSame( 'reject', LoginConfirmation::decision( true, array( 'log' => 'a', 'pwd' => 'secret', LoginConfirmation::FIELD => 'filled' ), false, false ) );
	}

	public function test_gap_rows_do_not_send_data(): void {
		$off       = ( new GapCheck( 'captcha-login', static fn(): string => '0' ) )->run( new ScanContext() )[0];
		$on        = ( new GapCheck( 'captcha-login', static fn(): string => '1' ) )->run( new ScanContext() )[0];
		$passwords = ( new GapCheck( 'compromised-passwords', static fn(): string => '0' ) )->run( new ScanContext() )[0];
		$listed    = ( new GapCheck( 'compromised-passwords', static fn(): string => '1' ) )->run( new ScanContext() )[0];
		$unread    = ( new GapCheck(
			'captcha-login',
			static function (): string {
				throw new RuntimeException( 'unavailable' );
			}
		) )->run( new ScanContext() )[0];

		self::assertSame( 'warn', $off->state );
		self::assertStringContainsString( 'people never see', $off->summary );
		self::assertStringNotContainsString( 'safe', $off->summary );
		self::assertSame( 'enable-login-confirm', StartHere::control( $off )['operation'] );

		self::assertSame( 'pass', $on->state );
		self::assertStringContainsString( 'hidden field', $on->summary );
		self::assertStringContainsString( 'sign-in question', $on->summary );
		self::assertSame( 'disable-login-confirm', StartHere::control( $on )['operation'] );

		self::assertStringContainsString( 'only the first 5 characters of a hash', $passwords->summary );
		self::assertSame( 'enable-common-passwords', StartHere::control( $passwords )['operation'] );
		self::assertStringContainsString( 'cannot sign in until it is changed', $listed->summary );
		self::assertStringContainsString( 'Passwords are never sent', $listed->summary );
		self::assertSame( 'disable-common-passwords', StartHere::control( $listed )['operation'] );

		self::assertSame( 'unknown', $unread->state );
		self::assertStringContainsString( 'does not send', $unread->summary );
		self::assertNull( StartHere::control( $unread ) );

		$hints = ( new GapCheck( 'login-hints', static fn(): string => '0' ) )->run( new ScanContext() )[0];
		$one   = ( new GapCheck( 'login-hints', static fn(): string => '1' ) )->run( new ScanContext() )[0];
		self::assertSame( 'warn', $hints->state );
		self::assertStringContainsString( 'does not send login attempts', $hints->summary );
		self::assertStringNotContainsString( 'safe', $hints->summary );
		self::assertSame( 'enable-login-hints', StartHere::control( $hints )['operation'] );
		self::assertSame( 'pass', $one->state );
		self::assertStringContainsString( 'one message', $one->summary );
		self::assertSame( 'disable-login-hints', StartHere::control( $one )['operation'] );
		self::assertSame(
			array(
				'empty_username'      => 'The username field is empty.',
				'amsec_generic_login' => 'The username or password is incorrect.',
			),
			LoginHints::generic(
				true,
				array(
					'empty_username'     => 'The username field is empty.',
					'invalid_username'   => 'Unknown username.',
					'incorrect_password' => 'The password you entered for the username ada is incorrect.',
				)
			)
		);
		self::assertArrayHasKey( 'invalid_username', LoginHints::generic( false, array( 'invalid_username' => 'Unknown username.' ) ) );
	}
}
