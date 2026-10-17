<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Login;

defined( 'ABSPATH' ) || exit;

final class RequiredTotpPolicy {
	public const OPTION = 'amsec_required_totp_policy';
	public const META   = 'amsec_required_totp_grace';
	public const GRACE  = 604800;

	public static function coveredAccount( bool $administrator, array $roles ): bool {
		return $administrator || in_array( 'editor', $roles, true );
	}

	public function generation(): ?string {
		$value = get_option( self::OPTION, '' );
		if ( '' === $value ) {
			return null;
		}
		if ( ! is_string( $value ) || ! preg_match( '/^[a-f0-9]{32}$/D', $value ) ) {
			throw new \RuntimeException( 'Policy unavailable.' );
		}
		return $value;
	}

	public function setEnabled( bool $enabled ): void {
		$value = $enabled ? bin2hex( random_bytes( 16 ) ) : '';
		update_option( self::OPTION, $value, false );
		if ( get_option( self::OPTION, '' ) !== $value ) {
			throw new \RuntimeException( 'Policy storage unavailable.' );
		}
	}

	public function grantGrace( int $id ): void {
		$generation = $this->generation();
		if ( null === $generation || $id < 1 || ! self::accountCovered( $id ) ) {
			throw new \RuntimeException( 'Account or policy unavailable.' );
		}
		$value = array(
			'generation' => $generation,
			'deadline'   => time() + self::GRACE,
		);
		update_user_meta( $id, self::META, $value );
		if ( get_user_meta( $id, self::META, true ) !== $value ) {
			throw new \RuntimeException( 'Grace storage unavailable.' );
		}
	}

	public function status( int $id ): string {
		$generation = $this->generation();
		if ( null === $generation || ! self::accountCovered( $id ) ) {
			return 'off';
		}
		if ( ( new WordPressTotpStore( $GLOBALS['wpdb'] ) )->isEnrolled( $id ) ) {
			return 'enrolled';
		}
		return RequiredTotpState::evaluate( get_user_meta( $id, self::META, true ), $generation, time() );
	}

	public function authenticate( mixed $user, string $username, string $password ): mixed {
		if ( ! $user instanceof \WP_User || ! self::coveredAccount( user_can( $user, 'manage_options' ), is_array( $user->roles ) ? $user->roles : array() ) || TotpAuthentication::isApiRequest( defined( 'REST_REQUEST' ) && REST_REQUEST, defined( 'WP_CLI' ) && WP_CLI, defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) || '' === $password || ! wp_check_password( $password, $user->user_pass, $user->ID ) ) {
			return $user;
		}
		try {
			$status = $this->status( $user->ID );
			if ( 'new' === $status ) {
				$this->grantGrace( $user->ID );
				$status = $this->status( $user->ID );
			}
			if ( in_array( $status, array( 'off', 'enrolled', 'grace' ), true ) ) {
				return $user;
			}
		} catch ( \Throwable ) {
			return new \WP_Error( 'amsec_policy_unavailable', __( 'Administrator verification policy is unavailable. Contact the site owner for recovery.', 'amazing-security' ) );
		}
		return new \WP_Error( 'amsec_enrollment_required', __( 'Your verification enrollment period has ended. Ask an enrolled administrator to grant a new grace period, or use host-level recovery.', 'amazing-security' ) );
	}

	private static function accountCovered( int $id ): bool {
		$user = get_userdata( $id );
		return $user instanceof \WP_User && self::coveredAccount( user_can( $user, 'manage_options' ), is_array( $user->roles ) ? $user->roles : array() );
	}

	public function recovery( array $args, array $assoc ): void {
		if ( array() !== $args || array() !== $assoc ) {
			\WP_CLI::error( 'This command accepts no arguments.' );
		}
		try {
			$this->setEnabled( false );
		} catch ( \Throwable ) {
			\WP_CLI::error( 'Could not disable the required verification policy.' );
		}
		( new \AmazingPlugins\Security\Activity\ActivityHooks( new \AmazingPlugins\Security\Activity\ActivityRepository( $GLOBALS['wpdb'] ) ) )->record( 'totp_policy_changed', 0, 'disable' );
		\WP_CLI::success( 'Required verification policy is off. Voluntary enrolled factors remain active.' );
	}
}
