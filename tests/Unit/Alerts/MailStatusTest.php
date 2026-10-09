<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Alerts;

use AmazingPlugins\Security\Alerts\MailStatus;
use PHPUnit\Framework\TestCase;

final class MailStatusTest extends TestCase {
	public function test_valid_admin_email_is_configured(): void {
		$status = MailStatus::assess( 'owner@example.test' );
		self::assertTrue( $status['configured'] );
		self::assertSame( 'owner@example.test', $status['email'] );
		self::assertStringContainsString( 'WordPress mail', $status['summary'] );
	}

	public function test_missing_admin_email_is_not_configured(): void {
		$status = MailStatus::assess( '' );
		self::assertFalse( $status['configured'] );
		self::assertStringContainsString( 'missing or invalid', $status['summary'] );
	}
}
