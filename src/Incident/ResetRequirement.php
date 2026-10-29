<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Incident;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Activity\ActivityHooks;
use AmazingPlugins\Security\Activity\ActivityRepository;

final class ResetRequirement {
	public const KEY = 'amsec_password_reset_required';

	public function required( int $id ): bool {
		return '1' === get_user_meta( $id, self::KEY, true );
	}

	public function requireReset( int $id ): void {
		if ( $id < 1 || ! get_userdata( $id ) ) {
			throw new \RuntimeException( 'Account unavailable.' );
		}
		update_user_meta( $id, self::KEY, '1' );
		if ( ! $this->required( $id ) ) {
			throw new \RuntimeException( 'Reset requirement could not be stored.' );
		}
	}

	public function clear( int $id ): void {
		if ( ! $this->required( $id ) ) {
			return;
		}
		delete_user_meta( $id, self::KEY );
		if ( $this->required( $id ) ) {
			throw new \RuntimeException( 'Reset requirement could not be cleared.' );
		}
		( new ActivityHooks( new ActivityRepository( $GLOBALS['wpdb'] ) ) )->record( 'password_reset_cleared', $id );
	}

	public function authenticate( mixed $user, string $username, string $password ): mixed {
		if ( $user instanceof \WP_User && $this->required( $user->ID ) && '' !== $password && wp_check_password( $password, $user->user_pass, $user->ID ) ) {
			return new \WP_Error( 'amsec_reset_required', __( 'Reset your password before signing in. Use the WordPress lost-password page or contact the site administrator.', 'amazingplugins-security-scanner' ) );
		}
		return $user;
	}

	public function passwordReset( \WP_User $user ): void {
		$this->clear( $user->ID );
	}

	public function profileUpdated( int $id, \WP_User $old ): void {
		$current = get_userdata( $id );
		if ( $current && ! hash_equals( $old->user_pass, $current->user_pass ) ) {
			$this->clear( $id );
		}
	}

	public function recovery( array $args, array $assoc ): void {
		if ( count( $args ) !== 1 || array() !== $assoc || ! ctype_digit( (string) $args[0] ) || (int) $args[0] < 1 || ! get_userdata( (int) $args[0] ) ) {
			\WP_CLI::error( 'Pass exactly one existing user ID.' );
		}
		try {
			$this->clear( (int) $args[0] );
		} catch ( \Throwable ) {
			\WP_CLI::error( 'Could not clear the reset requirement.' );
		}
		\WP_CLI::success( 'Reset requirement cleared for the selected account.' );
	}
}
