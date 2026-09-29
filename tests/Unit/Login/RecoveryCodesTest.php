<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Login;

use AmazingPlugins\Security\Login\RecoveryCodes;
use PHPUnit\Framework\TestCase;

final class RecoveryCodesTest extends TestCase {
	public function test_ten_unique_codes_are_hashed(): void {
		$codes = ( new RecoveryCodes() )->generate();
		self::assertCount( 10, $codes );
		self::assertCount( 10, array_unique( $codes ) );
		$hashes = ( new RecoveryCodes() )->hashAll( $codes );
		self::assertCount( 10, $hashes );
		self::assertTrue( password_verify( $codes[0], $hashes[0] ) );
		self::assertFalse( in_array( $codes[0], $hashes, true ) );
	}
}
