<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

/** A short pointer tour of the side menu. Nothing runs or changes; it only labels where things are. */
final class FirstRun {
	/** WordPress stores this id in the account's dismissed pointers once the tour ends. */
	public const POINTER = 'amsec_tour';

	public static function assets(): void {
		if ( ! Brand::onScreen() || ! current_user_can( 'manage_options' ) || self::dismissed( get_current_user_id() ) ) {
			return;
		}
		wp_enqueue_style( 'wp-pointer' );
		wp_enqueue_script( 'amazing-security-tour', plugins_url( 'assets/admin-tour.js', AMAZING_SECURITY_FILE ), array( 'wp-pointer' ), '0.1.1', true );
		wp_localize_script(
			'amazing-security-tour',
			'amsecTour',
			array(
				'pointer' => self::POINTER,
				'steps'   => self::steps(),
				'phone'   => array(
					'target' => '#wp-admin-bar-menu-toggle',
					'edge'   => 'top',
					'title'  => __( 'Menu', 'amazing-security' ),
					'text'   => __( 'Open the menu, then tap Amazing Security. Scan, Recommendations, Log In & Register, Traffic, Files, Records, Settings and AI & MCP are under it.', 'amazing-security' ),
				),
				'next'    => __( 'Next', 'amazing-security' ),
				'done'    => __( 'Done', 'amazing-security' ),
				'skip'    => __( 'Skip tour', 'amazing-security' ),
			)
		);
	}

	private static function dismissed( int $user ): bool {
		$list = explode( ',', (string) get_user_meta( $user, 'dismissed_wp_pointers', true ) );
		return in_array( self::POINTER, $list, true );
	}

	/**
	 * @return list<array{target: string, title: string, text: string}>
	 */
	public static function steps(): array {
		$link = static fn ( string $page ): string => '#adminmenu a[href$="page=' . $page . '"]';
		return array(
			array(
				'target' => $link( 'amazing-security' ),
				'title'  => __( 'Scan', 'amazing-security' ),
				'text'   => __( 'Reads this site and lists what it finds. A scan does not change anything.', 'amazing-security' ),
			),
			array(
				'target' => $link( 'amsec-recommendations' ),
				'title'  => __( 'Recommendations', 'amazing-security' ),
				'text'   => __( 'Where to start, and which protections are still off.', 'amazing-security' ),
			),
			array(
				'target' => $link( 'amsec-accounts' ),
				'title'  => __( 'Log In & Register', 'amazing-security' ),
				'text'   => __( 'Sign-in checks and authenticator status. Each one stays off until you turn it on.', 'amazing-security' ),
			),
			array(
				'target' => $link( 'amsec-traffic-guard' ),
				'title'  => __( 'Traffic', 'amazing-security' ),
				'text'   => __( 'Request limits and rules. Each one stays off until you turn it on.', 'amazing-security' ),
			),
			array(
				'target' => $link( 'amsec-files' ),
				'title'  => __( 'Files', 'amazing-security' ),
				'text'   => __( 'File checks. A fix only happens after you approve it.', 'amazing-security' ),
			),
			array(
				'target' => $link( 'amsec-records' ),
				'title'  => __( 'Records', 'amazing-security' ),
				'text'   => __( 'The local record of sign-ins and account changes.', 'amazing-security' ),
			),
			array(
				'target' => $link( 'amsec-settings' ),
				'title'  => __( 'Settings', 'amazing-security' ),
				'text'   => __( 'Email notices and the weekly digest. Both are off by default.', 'amazing-security' ),
			),
			array(
				'target' => $link( 'amsec-assistant' ),
				'title'  => __( 'AI & MCP', 'amazing-security' ),
				'text'   => __( 'Optional access for an AI assistant.', 'amazing-security' ),
			),
		);
	}
}
