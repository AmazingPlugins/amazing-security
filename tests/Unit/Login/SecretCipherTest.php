<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Login;

use AmazingPlugins\Security\Login\SecretCipher;
use PHPUnit\Framework\TestCase;

final class SecretCipherTest extends TestCase {
	public function test_encrypt_decrypt_tamper_and_key_change(): void {
		$cipher = new SecretCipher( str_repeat( 'a', 64 ) );
		$envelope = $cipher->encrypt( 'private-seed' );
		self::assertNotSame( 'private-seed', $envelope );
		self::assertSame( 'private-seed', $cipher->decrypt( $envelope ) );
		self::assertNull( ( new SecretCipher( str_repeat( 'b', 64 ) ) )->decrypt( $envelope ) );
		self::assertNull( $cipher->decrypt( substr( $envelope, 0, -2 ) . 'xx' ) );
	}
}
