<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Login;

use AmazingPlugins\Security\Integrity\WordPressOptions;

final class LoginRecoveryCommand {
	public function disableLogin( array $args, array $assocArgs ): void {
		if ( array() !== $args || array() !== $assocArgs ) {
			\WP_CLI::error( 'This command does not accept arguments.' );
		}
		$settings = new WordPressLoginSettings( new WordPressOptions() );
		$settings->setRateMode( 'off' );
		$settings->setXmlRpcAuthDisabled( false );
		\WP_CLI::success( 'Amazing Security login rate blocking and XML-RPC restriction are off.' );
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
