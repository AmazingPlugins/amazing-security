<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Free\Notices;

defined( 'ABSPATH' ) || exit;

/** Email copy for an administrator role or a limited sign-in. Off until the option is on. */
final class Notice {
	public const OPTION = 'amsec_event_mail';

	public static function flag( mixed $value ): string {
		return '1' === $value ? '1' : '0';
	}

	/**
	 * @return array{subject: string, body: string}|null
	 */
	public static function message( string $enabled, string $kind, string $login ): ?array {
		if ( '1' !== $enabled ) {
			return null;
		}
		if ( 'administrator' === $kind ) {
			$login = trim( $login );
			if ( '' === $login || strlen( $login ) > 60 || 1 !== preg_match( '/^[A-Za-z0-9 _.@-]+$/', $login ) ) {
				$login = 'an account';
			}
			return array(
				'subject' => 'Administrator role added',
				'body'    => 'An account was given the administrator role: ' . $login . '.',
			);
		}
		if ( 'limited' === $kind ) {
			return array(
				'subject' => 'Sign-in limited',
				'body'    => 'A sign-in was limited by the local repeat check.',
			);
		}
		return null;
	}
}
