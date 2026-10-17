<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Free\Guide;

defined( 'ABSPATH' ) || exit;

/** Counts local protections that are on. A full score does not mean the site is clean. */
final class Score {
	/** @var array<string, string> */
	public const FLAGS = array(
		'amsec_login_confirm'         => '1',
		'amsec_generic_login_errors'  => '1',
		'amsec_hide_author_archives'  => '1',
		'amsec_hide_rest_users'       => '1',
		'amsec_hotlink'               => '1',
		'amsec_approve_registrations' => '1',
		'amsec_email_factor'          => '1',
		'amsec_login_challenge'       => '1',
	);

	/**
	 * @param array<string, mixed> $options
	 * @return array{on: int, total: int}
	 */
	public static function tally( array $options ): array {
		$on = 0;
		foreach ( self::FLAGS as $key => $expected ) {
			if ( (string) ( $options[ $key ] ?? '0' ) === $expected ) {
				++$on;
			}
		}
		$idle = (string) ( $options['amsec_idle_minutes'] ?? '0' );
		if ( in_array( $idle, array( '15', '30', '60' ), true ) ) {
			++$on;
		}
		return array(
			'on'    => $on,
			'total' => count( self::FLAGS ) + 1,
		);
	}

	/**
	 * Local preset. It does not turn on breach lookups, vulnerability lookups, or request blocking.
	 *
	 * @return array<string, string>
	 */
	public static function preset( string $name ): array {
		if ( 'shop' !== $name && 'blog' !== $name ) {
			return array();
		}
		return array(
			'amsec_login_confirm'         => '1',
			'amsec_generic_login_errors'  => '1',
			'amsec_hide_author_archives'  => '1',
			'amsec_hide_rest_users'       => '1',
			'amsec_hotlink'               => '1',
			'amsec_approve_registrations' => '1',
			'amsec_idle_minutes'          => '30',
		);
	}
}
