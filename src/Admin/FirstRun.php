<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

defined( 'ABSPATH' ) || exit;

/** A short pointer tour of the side menu. Nothing runs or changes; it only labels where things are. */
final class FirstRun {
	/** WordPress stores this id in the account's dismissed pointers once the tour ends. */
	public const POINTER = 'amsec_tour';

	public static function assets(): void {
		if ( ! Brand::onScreen() || ! current_user_can( 'manage_options' ) || self::dismissed( get_current_user_id() ) ) {
			return;
		}
		wp_enqueue_style( 'wp-pointer' );
		wp_enqueue_script( 'amazing-security-tour', plugins_url( 'assets/admin-tour.js', AMAZING_SECURITY_FILE ), array( 'wp-pointer' ), '0.1.4', true );
		wp_localize_script(
			'amazing-security-tour',
			'amsecTour',
			array(
				'pointer' => self::POINTER,
				'steps'   => self::steps( false !== get_option( 'amazing_security_latest_run', false ) ),
				'phone'   => array(
					'target' => '#wp-admin-bar-menu-toggle',
					'edge'   => 'top',
					'title'  => __( 'Menu', 'amsec-security-scanner' ),
					'text'   => __( 'Every section of this plugin is in the admin menu, under Security Scanner.', 'amsec-security-scanner' ),
				),
				'next'    => __( 'Next', 'amsec-security-scanner' ),
				'done'    => __( 'Done', 'amsec-security-scanner' ),
				'skip'    => __( 'Skip tour', 'amsec-security-scanner' ),
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
				'target' => $link( 'amazing-security' ),
				'title'  => __( 'Scan', 'amsec-security-scanner' ),
				'text'   => __( 'Reads this site and lists what it finds. A scan does not change anything.', 'amsec-security-scanner' ),
			),
			array(
				'target' => $link( 'amsec-recommendations' ),
				'title'  => __( 'Recommendations', 'amsec-security-scanner' ),
				'text'   => __( 'Where to start, and which protections are still off.', 'amsec-security-scanner' ),
			),
			array(
				'target' => $link( 'amsec-accounts' ),
				'title'  => __( 'Log In & Register', 'amsec-security-scanner' ),
				'text'   => __( 'Sign-in checks and authenticator status. Each one stays off until you turn it on.', 'amsec-security-scanner' ),
			),
			array(
				'target' => $link( 'amsec-traffic-guard' ),
				'title'  => __( 'Traffic', 'amsec-security-scanner' ),
				'text'   => __( 'Request limits and rules. Each one stays off until you turn it on.', 'amsec-security-scanner' ),
			),
			array(
				'target' => $link( 'amsec-files' ),
				'title'  => __( 'Files', 'amsec-security-scanner' ),
				'text'   => __( 'File checks. A fix only happens after you approve it.', 'amsec-security-scanner' ),
			),
			array(
				'target' => $link( 'amsec-records' ),
				'title'  => __( 'Records', 'amsec-security-scanner' ),
				'text'   => __( 'The local record of sign-ins and account changes.', 'amsec-security-scanner' ),
			),
			array(
				'target' => $link( 'amsec-settings' ),
				'title'  => __( 'Settings', 'amsec-security-scanner' ),
				'text'   => __( 'Email notices and the weekly digest. Both are off by default.', 'amsec-security-scanner' ),
			),
			array(
				'target' => $link( 'amsec-assistant' ),
				'title'  => __( 'AI & MCP', 'amsec-security-scanner' ),
				'text'   => __( 'Optional access for an AI assistant.', 'amsec-security-scanner' ),
			),
			array(
				'target' => '.amsec-scan-button',
				'edge'   => 'top',
				'title'  => $scanned ? __( 'Rescan button', 'amsec-security-scanner' ) : __( 'Scan button', 'amsec-security-scanner' ),
				'text'   => $scanned ? __( 'Runs the checks again after you change something. It does not change the site.', 'amsec-security-scanner' ) : __( 'Nothing runs until you press this.', 'amsec-security-scanner' ),
			),
		);
		if ( $scanned ) {
			$steps[] = array(
				'target' => '.amsec-scan .amsec-cats',
				'edge'   => 'top',
				'title'  => __( 'Results', 'amsec-security-scanner' ),
				'text'   => __( 'Findings are sorted into these tabs. The number is how many are in each.', 'amsec-security-scanner' ),
			);
		}
		return $steps;
	}
}
