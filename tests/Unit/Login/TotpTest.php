<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Login;

use AmazingPlugins\Security\Login\Totp;
use PHPUnit\Framework\TestCase;

final class TotpTest extends TestCase {
	public function test_rfc_vector_skew_and_replay(): void {
		$totp   = new Totp();
		$secret = '12345678901234567890';
		self::assertSame( 1, $totp->verify( $secret, '287082', 59, null ) );
		self::assertSame( 1, $totp->verify( $secret, '287082', 89, null ) );
		self::assertNull( $totp->verify( $secret, '287082', 59, 1 ) );
		self::assertNull( $totp->verify( $secret, '287082', 119, null ) );
		self::assertNull( $totp->verify( $secret, '28708', 59, null ) );
	}
}
