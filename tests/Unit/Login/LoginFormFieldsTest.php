<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Login;

use AmazingPlugins\Security\Login\LoginFormFields;
use PHPUnit\Framework\TestCase;

final class LoginFormFieldsTest extends TestCase {
	public function test_optional_factor_field_is_named_and_labeled(): void {
		ob_start();
		( new LoginFormFields() )->render();
		$html = ob_get_clean();
		self::assertStringContainsString( 'name="amsec_otp"', $html );
		self::assertStringContainsString( 'Verification or recovery code', $html );
	}
}
