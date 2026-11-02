<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Login;

defined( 'ABSPATH' ) || exit;

final class LoginFormFields {
	/** The password form stays username and password. The code has its own screen. */
	public function render(): void {
	}

	public function step(): void {
		echo '<p class="ironlatch-login-factor"><label for="ironlatch-otp">' . esc_html__( 'Verification or recovery code', 'ironlatch-security-scanner' ) . '</label><input class="input" type="text" id="ironlatch-otp" name="ironlatch_otp" inputmode="numeric" autocomplete="one-time-code" maxlength="24"></p>';
	}
}
