<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

defined( 'ABSPATH' ) || exit;

/** A short pointer tour of the side menu. Nothing runs or changes; it only labels where things are. */
final class FirstRun {
	/** WordPress stores this id in the account's dismissed pointers once the tour ends. */
	public const POINTER = 'ironlatch_tour';

	public static function assets(): void {
		if ( ! Brand::onScreen() || ! current_user_can( 'manage_options' ) || self::dismissed( get_current_user_id() ) ) {
			return;
		}
		wp_enqueue_style( 'wp-pointer' );
		wp_enqueue_script( 'ironlatch-security-scanner-tour', plugins_url( 'assets/admin-tour.js', IRONLATCH_SECURITY_SCANNER_FILE ), array( 'wp-pointer' ), '0.1.6', true );
		wp_localize_script(
			'ironlatch-security-scanner-tour',
			'ironlatchTour',
			array(
				'pointer' => self::POINTER,
				'steps'   => self::steps( false !== get_option( 'ironlatch_security_scanner_latest_run', false ) ),
				'phone'   => array(
					'target' => '#wp-admin-bar-menu-toggle',
					'edge'   => 'top',
					'title'  => __( 'Menu', 'ironlatch-security-scanner' ),
					'text'   => __( 'Every section of this plugin is in the admin menu, under Security Scanner.', 'ironlatch-security-scanner' ),
				),
				'next'    => __( 'Next', 'ironlatch-security-scanner' ),
				'done'    => __( 'Done', 'ironlatch-security-scanner' ),
				'skip'    => __( 'Skip tour', 'ironlatch-security-scanner' ),
			)
		);
	}

	private static function dismissed( int $user ): bool {
		$list = explode( ',', (string) get_user_meta( $user, 'dismissed_wp_pointers', true ) );
		return in_array( self::POINTER, $list, true );
	}

	/**
	 * @return list<array{target: string, title: string, text: string, edge?: string}>
	 */
	public static function steps( bool $scanned = false ): array {
		$link  = static fn ( string $page ): string => '#adminmenu a[href$="page=' . $page . '"]';
		$steps = array(
			array(
				'target' => $link( 'ironlatch-security-scanner' ),
				'title'  => __( 'Scan', 'ironlatch-security-scanner' ),
				'text'   => __( 'Reads this site and lists what it finds. A scan does not change anything.', 'ironlatch-security-scanner' ),
			),
			array(
				'target' => $link( 'ironlatch-recommendations' ),
				'title'  => __( 'Recommendations', 'ironlatch-security-scanner' ),
				'text'   => __( 'Where to start, and which protections are still off.', 'ironlatch-security-scanner' ),
			),
			array(
				'target' => $link( 'ironlatch-accounts' ),
				'title'  => __( 'Log In & Register', 'ironlatch-security-scanner' ),
				'text'   => __( 'Sign-in checks and authenticator status. Each one stays off until you turn it on.', 'ironlatch-security-scanner' ),
			),
			array(
				'target' => $link( 'ironlatch-traffic-guard' ),
				'title'  => __( 'Traffic', 'ironlatch-security-scanner' ),
				'text'   => __( 'Request limits and rules. Each one stays off until you turn it on.', 'ironlatch-security-scanner' ),
			),
			array(
				'target' => $link( 'ironlatch-files' ),
				'title'  => __( 'Files', 'ironlatch-security-scanner' ),
				'text'   => __( 'File checks. A fix only happens after you approve it.', 'ironlatch-security-scanner' ),
			),
			array(
				'target' => $link( 'ironlatch-records' ),
				'title'  => __( 'Records', 'ironlatch-security-scanner' ),
				'text'   => __( 'The local record of sign-ins and account changes.', 'ironlatch-security-scanner' ),
			),
			array(
				'target' => $link( 'ironlatch-settings' ),
				'title'  => __( 'Settings', 'ironlatch-security-scanner' ),
				'text'   => __( 'Email notices and the weekly digest. Both are off by default.', 'ironlatch-security-scanner' ),
			),
			array(
				'target' => $link( 'ironlatch-assistant' ),
				'title'  => __( 'AI & MCP', 'ironlatch-security-scanner' ),
				'text'   => __( 'Optional access for an AI assistant.', 'ironlatch-security-scanner' ),
			),
			array(
				'target' => '.ironlatch-scan-button',
				'edge'   => 'top',
				'title'  => $scanned ? __( 'Rescan button', 'ironlatch-security-scanner' ) : __( 'Scan button', 'ironlatch-security-scanner' ),
				'text'   => $scanned ? __( 'Runs the checks again after you change something. It does not change the site.', 'ironlatch-security-scanner' ) : __( 'Nothing runs until you press this.', 'ironlatch-security-scanner' ),
			),
		);
		if ( $scanned ) {
			$steps[] = array(
				'target' => '.ironlatch-scan .ironlatch-cats',
				'edge'   => 'top',
				'title'  => __( 'Results', 'ironlatch-security-scanner' ),
				'text'   => __( 'Findings are sorted into these tabs. The number is how many are in each.', 'ironlatch-security-scanner' ),
			);
		}
		return $steps;
	}
}
