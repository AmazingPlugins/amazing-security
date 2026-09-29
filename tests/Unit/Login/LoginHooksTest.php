<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Login;

use AmazingPlugins\Security\Login\LoginHooks;
use PHPUnit\Framework\TestCase;

final class LoginHooksTest extends TestCase {
	public function test_only_interactive_post_password_requests_are_limited(): void {
		self::assertTrue( LoginHooks::isInteractiveRequest( array( 'REQUEST_METHOD' => 'POST' ), array( 'log' => 'owner', 'pwd' => 'guess' ), false, false ) );
		self::assertTrue( LoginHooks::isInteractiveRequest( array( 'REQUEST_METHOD' => 'POST' ), array( 'username' => 'owner', 'password' => 'guess' ), false, false ) );
		self::assertFalse( LoginHooks::isInteractiveRequest( array( 'REQUEST_METHOD' => 'GET' ), array(), false, false ) );
		self::assertFalse( LoginHooks::isInteractiveRequest( array( 'REQUEST_METHOD' => 'POST' ), array( 'log' => 'owner', 'pwd' => 'guess' ), true, false ) );
		self::assertFalse( LoginHooks::isInteractiveRequest( array( 'REQUEST_METHOD' => 'POST' ), array( 'log' => 'owner', 'pwd' => 'guess' ), false, true ) );
		self::assertFalse( LoginHooks::isInteractiveRequest( array( 'REQUEST_METHOD' => 'POST' ), array( 'user_login' => 'owner' ), false, false ) );
	}
}
