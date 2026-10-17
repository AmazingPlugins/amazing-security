<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Login;

defined( 'ABSPATH' ) || exit;

/** Required TOTP policy UI retired — use a dedicated two-factor plugin. */
final class RequiredTotpAction {
	public function handle(): void {
		wp_die( esc_html__( 'Amazing Security no longer manages required authenticator policy. Use a dedicated two-factor plugin.', 'amazing-security' ), '', array( 'response' => 410 ) );
	}
}
