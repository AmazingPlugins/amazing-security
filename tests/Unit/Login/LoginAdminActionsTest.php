<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Login;

use AmazingPlugins\Security\Admin\LoginSettingsAction;
use AmazingPlugins\Security\Admin\TotpAction;
use PHPUnit\Framework\TestCase;

final class LoginAdminActionsTest extends TestCase {
	public function test_settings_parser_rejects_unlisted_modes(): void {
		self::assertSame( array( 'observe', true, false ), LoginSettingsAction::parse( array( 'rate_mode' => 'observe', 'xmlrpc_disabled' => '1' ) ) );
		$this->expectException( \InvalidArgumentException::class );
		LoginSettingsAction::parse( array( 'rate_mode' => 'unlimited' ) );
	}

	public function test_totp_actions_are_for_current_administrator_only(): void {
		self::assertFalse( TotpAction::canManage( 7, 8, true, true ) );
		self::assertFalse( TotpAction::canManage( 7, 7, false, true ) );
		self::assertFalse( TotpAction::canManage( 7, 7, true, false ) );
		self::assertTrue( TotpAction::canManage( 7, 7, true, true ) );
	}
}
