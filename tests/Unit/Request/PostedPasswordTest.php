<?php

declare(strict_types=1);

namespace {
if ( ! function_exists( 'wp_unslash' ) ) {
	function wp_unslash( $value ) { return is_string( $value ) ? stripslashes( $value ) : $value; }
}
if ( ! function_exists( 'wp_check_invalid_utf8' ) ) {
	function wp_check_invalid_utf8( $text ) { return is_string( $text ) && 1 === preg_match( '//u', $text ) ? $text : ''; }
}
}

namespace AmazingPlugins\Security\Tests\Unit\Request {

use AmazingPlugins\Security\Request\PostedPassword;
use PHPUnit\Framework\TestCase;

final class PostedPasswordTest extends TestCase {
	protected function tearDown(): void {
		$_POST = array();
	}

	public function testReturnsPasswordAsTyped(): void {
		$_POST['password'] = 'p@ss <b>%41</b>  ';
		$this->assertSame( 'p@ss <b>%41</b>  ', PostedPassword::read( 'password' ) );
	}

	public function testUnslashes(): void {
		$_POST['password'] = 'it\\\'s';
		$this->assertSame( "it's", PostedPassword::read( 'password' ) );
	}

	public function testMissingOrArrayIsNull(): void {
		$this->assertNull( PostedPassword::read( 'password' ) );
		$_POST['password'] = array( 'x' );
		$this->assertNull( PostedPassword::read( 'password' ) );
		$this->assertTrue( PostedPassword::rejected( 'password' ) );
	}

	public function testControlCharactersRejected(): void {
		$_POST['password'] = "abc\x01def";
		$this->assertNull( PostedPassword::read( 'password' ) );
		$this->assertTrue( PostedPassword::rejected( 'password' ) );
	}

	public function testOversizeRejected(): void {
		$_POST['password'] = str_repeat( 'a', 1025 );
		$this->assertNull( PostedPassword::read( 'password' ) );
		$this->assertSame( str_repeat( 'a', 1025 ), PostedPassword::read( 'password', 4096 ) );
	}

	public function testInvalidUtf8Rejected(): void {
		$_POST['password'] = "ab\xC3\x28";
		$this->assertNull( PostedPassword::read( 'password' ) );
	}

	public function testEmptyIsNotRejected(): void {
		$_POST['password'] = '';
		$this->assertFalse( PostedPassword::rejected( 'password' ) );
	}
}
}
