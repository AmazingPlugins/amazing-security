<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Login;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Integrity\WordPressOptions;

final class LoginRecoveryCommand {
	public function disableLogin( array $args, array $assocArgs ): void {
		if ( array() !== $args || array() !== $assocArgs ) {
			\WP_CLI::error( 'This command does not accept arguments.' );
		}
		$settings = new WordPressLoginSettings( new WordPressOptions() );
		$settings->setRateMode( 'off' );
		( new WordPressRateCounterStore( $GLOBALS['wpdb'] ) )->purge();
		$settings->setXmlRpcAuthDisabled( false );
		// Every sign-in check that can refuse a correct password. Pending approvals stay as they are.
		foreach ( array( 'amsec_email_factor', 'amsec_login_challenge', 'amsec_login_confirm', 'amsec_common_passwords', 'amsec_idle_minutes' ) as $option ) {
			update_option( $option, '0' );
		}
		\WP_CLI::success( 'Amazing Security sign-in limits, XML-RPC restriction, email code, sum question, hidden field, breached-password block and idle sign-out are off.' );
	}

	public function disableTotp( array $args, array $assocArgs ): void {
		$userId = $assocArgs['user'] ?? null;
		if ( array() !== $args || 1 !== count( $assocArgs ) || ! is_string( $userId ) || ! ctype_digit( $userId ) || (int) $userId < 1 || ! get_userdata( (int) $userId ) ) {
			\WP_CLI::error( 'Pass exactly one existing user ID with --user=<id>.' );
		}
		$store = new WordPressTotpStore( $GLOBALS['wpdb'] );
		if ( ! $store->disable( (int) $userId ) ) {
			\WP_CLI::error( 'Could not disable TOTP for this user.' );
		}
		update_user_meta( (int) $userId, 'amsec_totp_recovery_at', gmdate( 'Y-m-d H:i:s' ) );
		\WP_CLI::success( 'Amazing Security TOTP is off for the selected user. Re-enroll after signing in.' );
	}
}
