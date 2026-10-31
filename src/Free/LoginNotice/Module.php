<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Free\LoginNotice;

defined( 'ABSPATH' ) || exit;

/** Sends one plain sign-in email after an administrator login, when the option is on. */
final class Module {
	public static function boot(): void {
		add_action( 'wp_login', array( self::class, 'afterLogin' ), 10, 2 );
		add_action( 'admin_menu', array( Page::class, 'menu' ) );
		add_action( 'admin_post_amsec_login_notice_save', array( Page::class, 'save' ) );
	}

	public static function afterLogin( string $user_login, mixed $user ): void {
		// The login name is not part of the email.
		unset( $user_login );
		if ( ! $user instanceof \WP_User ) {
			return;
		}
		$now      = time();
		$decision = Decision::decide(
			self::option(),
			user_can( $user, 'manage_options' ),
			Decision::lastSent( get_user_meta( $user->ID, Decision::META, true ) ),
			$now
		);
		if ( 'send' !== $decision ) {
			return;
		}
		self::deliver( $user, $now );
	}

	private static function deliver( \WP_User $user, int $now ): void {
		$email = $user->user_email;
		if ( ! is_string( $email ) || ! is_email( $email ) ) {
			return;
		}
		$site = get_bloginfo( 'name' );
		if ( ! is_string( $site ) ) {
			$site = '';
		}
		$sent = wp_mail(
			$email,
			__( 'Sign-in email', 'amsec-security-scanner' ),
			Decision::body( $site, $now )
		);
		if ( true !== $sent ) {
			return;
		}
		update_user_meta( $user->ID, Decision::META, (string) $now );
	}

	private static function option(): string {
		$value = get_option( Decision::OPTION, '0' );
		return is_string( $value ) ? $value : '0';
	}
}
