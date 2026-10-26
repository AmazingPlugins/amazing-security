<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Login;

defined( 'ABSPATH' ) || exit;

final class LoginFormFields {
	/** The password form stays username and password. The code has its own screen. */
	public function render(): void {
	}

	public function step(): void {
		echo '<p class="amsec-login-factor"><label for="amsec-otp">' . esc_html__( 'Verification or recovery code', 'amazingplugins-security-scanner' ) . '</label><input class="input" type="text" id="amsec-otp" name="amsec_otp" inputmode="numeric" autocomplete="one-time-code" maxlength="24"></p>';
	}
}
