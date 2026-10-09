<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Login;

use AmazingPlugins\Security\Login\LoginFormFields;
use PHPUnit\Framework\TestCase;

final class LoginFormFieldsTest extends TestCase {
	public function test_password_form_does_not_ask_for_a_code(): void {
		ob_start();
		( new LoginFormFields() )->render();
		$html = ob_get_clean();
		self::assertStringNotContainsString( 'name="amsec_otp"', $html );
	}

	public function test_code_screen_asks_after_the_password(): void {
		ob_start();
		( new LoginFormFields() )->step();
		$html = ob_get_clean();
		self::assertStringContainsString( 'name="amsec_otp"', $html );
		self::assertStringContainsString( 'Verification or recovery code', $html );
	}
}
