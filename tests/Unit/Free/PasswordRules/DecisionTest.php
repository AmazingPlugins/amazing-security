<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Free\PasswordRules;

use AmazingPlugins\Security\Free\PasswordRules\Decision;
use PHPUnit\Framework\TestCase;

require_once dirname( __DIR__, 4 ) . '/src/Free/PasswordRules/Decision.php';

final class DecisionTest extends TestCase {
	public function test_allowed_on_values_are_only_eight_twelve_and_sixteen(): void {
		self::assertSame( array( '8', '12', '16' ), Decision::ALLOWED );
		self::assertSame( 'amsec_password_min_length', Decision::OPTION );
	}

	public function test_zero_and_other_stored_values_are_off(): void {
		foreach ( array( '0', '', '1', '7', '9', '10', '15', '18', '32', '08', '8 ', 'off', 'on' ) as $stored ) {
			self::assertSame( '0', Decision::normalize( $stored ) );
			self::assertSame( 0, Decision::minimum( $stored ) );
			self::assertFalse( Decision::rejects( $stored, 0, 'new' ) );
			self::assertFalse( Decision::rejects( $stored, 1, 'reset' ) );
		}
	}

	public function test_new_and_reset_passwords_shorter_than_the_minimum_are_rejected(): void {
		$cases = array(
			array( '8', 8 ),
			array( '12', 12 ),
			array( '16', 16 ),
		);
		foreach ( $cases as $case ) {
			$stored   = $case[0];
			$minimum  = $case[1];
			self::assertSame( $stored, Decision::normalize( $stored ) );
			self::assertSame( $minimum, Decision::minimum( $stored ) );
			self::assertTrue( Decision::rejects( $stored, 0, 'new' ) );
			self::assertTrue( Decision::rejects( $stored, $minimum - 1, 'new' ) );
			self::assertTrue( Decision::rejects( $stored, $minimum - 1, 'reset' ) );
			self::assertFalse( Decision::rejects( $stored, $minimum, 'new' ) );
			self::assertFalse( Decision::rejects( $stored, $minimum, 'reset' ) );
			self::assertFalse( Decision::rejects( $stored, $minimum + 4, 'new' ) );
		}
	}

	public function test_sign_in_is_not_rejected(): void {
		foreach ( array( '0', '8', '12', '16', 'nope' ) as $stored ) {
			self::assertFalse( Decision::rejects( $stored, 0, 'sign-in' ) );
			self::assertFalse( Decision::rejects( $stored, 1, 'sign-in' ) );
			self::assertFalse( Decision::rejects( $stored, 3, 'login' ) );
			self::assertFalse( Decision::rejects( $stored, 1, '' ) );
		}
	}

	public function test_extra_rules_stay_off_until_each_one_is_enabled(): void {
		self::assertNull( $this->check( 'new', 'a', '0', '0', '0', '0', '0', '0', 'admin', 'admin@example.com', true ) );
		self::assertSame( 'number', $this->check( 'new', 'Abcdefgh', '0', '1', '0', '0', '0', '0', '', '', false ) );
		self::assertNull( $this->check( 'new', 'Abcdefg1', '0', '1', '0', '0', '0', '0', '', '', false ) );
		self::assertSame( 'mixed', $this->check( 'new', 'abcdefg1', '0', '0', '1', '0', '0', '0', '', '', false ) );
		self::assertNull( $this->check( 'new', 'Abcdefg1', '0', '0', '1', '0', '0', '0', '', '', false ) );
		self::assertSame( 'symbol', $this->check( 'new', 'Abcdefg1', '0', '0', '0', '1', '0', '0', '', '', false ) );
		self::assertNull( $this->check( 'new', 'Abcdefg1!', '0', '0', '0', '1', '0', '0', '', '', false ) );
		self::assertSame( 'name', $this->check( 'new', 'helloAdmin!', '0', '0', '0', '0', '1', '0', 'admin', 'other@example.com', false ) );
		self::assertSame( 'name', $this->check( 'new', 'xxownerxx', '0', '0', '0', '0', '1', '0', 'ab', 'owner@example.com', false ) );
		self::assertNull( $this->check( 'new', 'helloab', '0', '0', '0', '0', '1', '0', 'ab', 'xy@example.com', false ) );
		self::assertSame( 'reuse', $this->check( 'reset', 'Abcdefg1!', '0', '0', '0', '0', '0', '1', '', '', true ) );
		self::assertNull( $this->check( 'reset', 'Abcdefg1!', '0', '0', '0', '0', '0', '1', '', '', false ) );
		self::assertNull( $this->check( 'sign-in', 'a', '16', '1', '1', '1', '1', '1', 'admin', 'admin@example.com', true ) );
	}

	public function test_length_is_still_the_first_failure(): void {
		self::assertSame( 'length', $this->check( 'new', 'short', '12', '1', '1', '1', '1', '1', 'admin', 'admin@example.com', true ) );
		self::assertNull( $this->check( 'new', 'Longerpass1!', '12', '1', '1', '1', '1', '0', 'other', 'other@example.com', false ) );
	}

	private function check(
		string $when,
		string $password,
		string $min,
		string $number,
		string $mixed,
		string $symbol,
		string $name,
		string $reuse,
		string $username,
		string $email,
		bool $matches
	): ?string {
		return Decision::violation( $when, $password, $min, $number, $mixed, $symbol, $name, $reuse, $username, $email, $matches );
	}
}
