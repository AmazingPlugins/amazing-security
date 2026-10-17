<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Free\Guide\Score;

/** Recommendations stay off the scan report. */
final class StartPanel {
	public static function register(): void {
		add_submenu_page(
			Submenu::PARENT,
			__( 'Recommendations', 'amazing-security' ),
			__( 'Recommendations', 'amazing-security' ),
			'manage_options',
			'amsec-recommendations',
			array( self::class, 'render' )
		);
	}

	public static function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'amazing-security' ), '', array( 'response' => 403 ) );
		}
		echo '<div class="wrap amazing-security-admin">';
		echo '<h1>' . esc_html__( 'Recommendations', 'amazing-security' ) . '</h1>';
		self::intro();
		self::next();
		echo '</div>';
	}

	public static function intro(): void {
		echo '<section class="amsec-start-home">';
		echo '<h2>' . esc_html__( 'Start here', 'amazing-security' ) . '</h2>';
		echo '<p>' . esc_html__( 'Amazing Security checks this WordPress site and keeps a local record of sign-ins and account changes. Protections stay off until you turn them on.', 'amazing-security' ) . '</p>';
		echo '<ol>';
		foreach ( self::steps() as $step ) {
			echo '<li>' . esc_html( $step ) . '</li>';
		}
		echo '</ol>';
		echo '<p>' . esc_html__( 'A firewall that runs before WordPress is a host service. This plugin scans and reports on WordPress, plugins, and themes. Soft fixes stay under Files when you approve them. It does not delete files from the scan.', 'amazing-security' ) . '</p>';
		echo '</section>';
	}

	public static function next(): void {
		$score = self::score();
		echo '<section class="amsec-start-home">';
		echo '<h2>' . esc_html__( 'What to do next', 'amazing-security' ) . '</h2>';
		echo '<p>' . esc_html__( 'Success on a row means that check passed. It does not mean every protection is on.', 'amazing-security' ) . '</p>';
		echo '<ul class="amsec-jumps">';
		foreach ( self::cards( $score['on'], $score['total'] ) as $card ) {
			echo '<li><a href="' . esc_url( $card['url'] ) . '"><strong>' . esc_html( $card['title'] ) . '</strong><span>' . esc_html( $card['note'] ) . '</span></a></li>';
		}
		echo '</ul></section>';
	}

	/**
	 * @return list<string>
	 */
	public static function steps(): array {
		return array(
			__( 'Run the scan.', 'amazing-security' ),
			__( 'Turn on the checks you want from Log In & Register, and from Traffic.', 'amazing-security' ),
			__( 'Check authenticator and passkey status under Log In & Register. Amazing Security does not enroll devices.', 'amazing-security' ),
		);
	}

	/**
	 * @return list<array{title: string, note: string, url: string}>
	 */
	public static function cards( int $on, int $total ): array {
		$admin   = static fn ( string $page ): string => admin_url( 'admin.php?page=' . $page );
		$cards   = array(
			array(
				'title' => __( 'Check authenticator and passkey status', 'amazing-security' ),
				'note'  => __( 'Status only. Install a dedicated plugin when it says not on this site.', 'amazing-security' ),
				'url'   => $admin( 'amsec-accounts' ) . '#verification',
			),
		);
		$cards[] = array(
			'title' => sprintf(
				/* translators: 1: protections on, 2: protections counted */
				__( '%1$d of %2$d protections are on', 'amazing-security' ),
				$on,
				$total
			),
			'note'  => __( 'Open Site review to turn on the ones you want. A full list does not mean the site is clean.', 'amazing-security' ),
			'url'   => $admin( 'amsec-guide' ),
		);
		$cards[] = array(
			'title' => __( 'If something looks wrong', 'amazing-security' ),
			'note'  => __( 'Review administrators, end other sessions, require a new password, then scan again.', 'amazing-security' ),
			'url'   => $admin( 'amsec-incident' ),
		);
		$cards[] = array(
			'title' => __( 'PHP in the uploads folder', 'amazing-security' ),
			'note'  => __( 'This plugin cannot prove what the server will run. You can add an Apache rule after you read it.', 'amazing-security' ),
			'url'   => $admin( 'amsec-uploads' ),
		);
		$cards[] = array(
			'title' => __( 'Watch a plugin or theme you choose', 'amazing-security' ),
			'note'  => __( 'Save a reference, then compare it later. A reference is not proof the code was clean.', 'amazing-security' ),
			'url'   => $admin( 'amsec-baselines' ),
		);
		$cards[] = array(
			'title' => __( 'Activity', 'amazing-security' ),
			'note'  => __( 'Stays off until you turn it on. It can store sign-ins, new accounts, role changes, and plugin changes. Visitor addresses are not stored.', 'amazing-security' ),
			'url'   => $admin( 'amsec-activity' ),
		);
		$cards[] = array(
			'title' => __( 'Email when an administrator is added', 'amazing-security' ),
			'note'  => __( 'Stays off. The weekly digest page is where you turn that email on.', 'amazing-security' ),
			'url'   => $admin( 'amsec-settings' ) . '#amsec-event-mail',
		);
		return $cards;
	}

	/**
	 * @return array{on: int, total: int}
	 */
	private static function score(): array {
		$options = array();
		foreach ( array_keys( Score::FLAGS ) as $key ) {
			$options[ $key ] = get_option( $key, '0' );
		}
		$options['amsec_idle_minutes'] = get_option( 'amsec_idle_minutes', '0' );
		return Score::tally( $options );
	}
}
