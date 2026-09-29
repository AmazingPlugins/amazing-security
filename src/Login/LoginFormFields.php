<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Login;

final class LoginFormFields {
	public function render(): void {
		echo '<p class="amsec-login-factor"><label for="amsec-otp">Verification or recovery code</label><input class="input" type="text" id="amsec-otp" name="amsec_otp" inputmode="numeric" autocomplete="one-time-code" maxlength="24"></p>';
	}
}
