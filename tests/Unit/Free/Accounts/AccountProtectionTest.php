<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Free\Accounts;

use AmazingPlugins\Security\Free\Accounts\AdminBreachBlock;
use AmazingPlugins\Security\Free\Accounts\EmailFactor;
use AmazingPlugins\Security\Free\Accounts\IdleLogout;
use AmazingPlugins\Security\Free\Accounts\LoginChallenge;
use AmazingPlugins\Security\Free\Accounts\LoginExtras;
use AmazingPlugins\Security\Free\Accounts\RegistrationApproval;
use AmazingPlugins\Security\Free\Accounts\Settings;
use PHPUnit\Framework\TestCase;

/**
 * Decision tests. They do not bootstrap WordPress or call the breach-list network.
 */
final class AccountProtectionTest extends TestCase {
	public function test_unknown_sign_in_choices_are_ignored(): void {
		self::assertSame( 'off', LoginExtras::rate( 'off' ) );
		self::assertSame( 'observe', LoginExtras::rate( 'observe' ) );
		self::assertSame( 'block', LoginExtras::rate( 'block' ) );
		self::assertNull( LoginExtras::rate( '0' ) );
		self::assertNull( LoginExtras::rate( 'limit' ) );
		self::assertSame( '0', LoginExtras::xmlrpc( '0' ) );
		self::assertSame( '1', LoginExtras::xmlrpc( '1' ) );
		self::assertNull( LoginExtras::xmlrpc( 'yes' ) );
	}

	public function test_idle_zero_does_not_log_out(): void {
		self::assertSame( 'off', IdleLogout::decision( 0, 1_000, 1_000 + ( 60 * 60 ) ) );
		self::assertSame( 'off', IdleLogout::decision( IdleLogout::minutes( '0' ), null, 1_000 ) );
		self::assertSame( 'stamp', IdleLogout::decision( 15, null, 1_000 ) );
	}

	public function test_idle_gap_logs_out(): void {
		$start = 1_700_000_000;
		self::assertSame( 'logout', IdleLogout::decision( 15, $start, $start + ( 15 * 60 ) + 1 ) );
		self::assertSame( 'stamp', IdleLogout::decision( 15, $start, $start + ( 15 * 60 ) ) );
	}

	public function test_pending_registration_blocks_only_flagged_users(): void {
		self::assertTrue( RegistrationApproval::blocks( true, '1' ) );
		self::assertTrue( RegistrationApproval::blocks( true, 1 ) );
		self::assertFalse( RegistrationApproval::blocks( true, '' ) );
		self::assertFalse( RegistrationApproval::blocks( true, null ) );
		self::assertFalse( RegistrationApproval::blocks( true, '0' ) );
		self::assertFalse( RegistrationApproval::blocks( false, '1' ) );
	}

	public function test_email_factor_stores_a_hash_not_the_code(): void {
		$code   = '482913';
		$record = EmailFactor::record( $code, 1_700_000_000, 'unit-key' );
		self::assertNotSame( $code, $record['hash'] );
		self::assertSame( hash_hmac( 'sha256', $code, 'unit-key' ), $record['hash'] );
		self::assertSame( 1_700_000_000 + 600, $record['expires'] );
		self::assertArrayNotHasKey( 'code', $record );
		foreach ( $record as $value ) {
			self::assertNotSame( $code, $value );
		}
		self::assertTrue( EmailFactor::matches( $code, $record, 1_700_000_000, 'unit-key' ) );
		self::assertSame( 'reject', EmailFactor::decision( true, false, false, 'secret', true, '000000', $record, 1_700_000_000, 'unit-key' ) );
	}

	public function test_email_factor_burns_the_code_after_five_wrong_tries(): void {
		$code   = '482913';
		$record = EmailFactor::record( $code, 1_700_000_000, 'unit-key' );
		for ( $i = 0; $i < EmailFactor::TRIES - 1; ++$i ) {
			$record = EmailFactor::failedTry( $record );
		}
		self::assertSame( 'accept', EmailFactor::decision( true, false, false, 'secret', true, $code, $record, 1_700_000_010, 'unit-key' ) );
		$record = EmailFactor::unpack( (string) json_encode( EmailFactor::failedTry( $record ) ) );
		self::assertSame( EmailFactor::TRIES, $record['tries'] );
		self::assertSame( 'reject', EmailFactor::decision( true, false, false, 'secret', true, $code, $record, 1_700_000_010, 'unit-key' ) );
		self::assertSame( 'reject', EmailFactor::decision( true, false, false, 'secret', true, '', $record, 1_700_000_030, 'unit-key' ), 'A burned code still waits for the resend interval.' );
		self::assertSame( 'send', EmailFactor::decision( true, false, false, 'secret', true, '', $record, 1_700_000_061, 'unit-key' ) );
	}

	public function test_breach_block_uses_a_fake_listed_callback(): void {
		$calls = 0;
		$fake  = static function ( string $password ) use ( &$calls ): bool {
			++$calls;
			return 'secret' === $password;
		};
		self::assertSame( 'block', AdminBreachBlock::decision( '1', true, 'secret', $fake ) );
		self::assertSame( 'allow', AdminBreachBlock::decision( '1', true, 'other', $fake ) );
		self::assertSame( 2, $calls );
		self::assertSame(
			'skip',
			AdminBreachBlock::decision(
				'0',
				true,
				'secret',
				static function (): bool {
					self::fail( 'listed must not run while the switch is off' );
				}
			)
		);
		self::assertSame(
			'skip',
			AdminBreachBlock::decision(
				'1',
				false,
				'secret',
				static function (): bool {
					self::fail( 'listed must not run for a non-administrator' );
				}
			)
		);
	}

	public function test_challenge_rejects_a_wrong_sum_and_a_filled_honeypot(): void {
		$token = str_repeat( 'a', 32 );
		self::assertSame( 'reject', LoginChallenge::decision( true, false, false, $token, '11', '4', '' ) );
		self::assertSame( 'reject', LoginChallenge::decision( true, false, false, $token, '11', '11', 'filled' ) );
		self::assertSame( 'reject', LoginChallenge::decision( true, false, false, '', '11', '11', '' ) );
		self::assertSame( 'allow', LoginChallenge::decision( true, false, false, $token, '11', '11', '' ) );
		self::assertSame( 'allow', LoginChallenge::decision( false, false, false, '', null, '', 'filled' ) );
	}

	public function test_settings_stay_off_and_ignore_the_common_password_switch(): void {
		$saved = Settings::fromPost( array( 'amsec_common_passwords' => '1' ) );
		self::assertSame(
			array(
				'amsec_idle_minutes'          => '0',
				'amsec_approve_registrations' => '0',
				'amsec_email_factor'          => '0',
				'amsec_login_challenge'       => '0',
				'amsec_login_erase_on_uninstall' => '0',
			),
			$saved
		);
		self::assertArrayNotHasKey( 'amsec_common_passwords', $saved );
	}
}
