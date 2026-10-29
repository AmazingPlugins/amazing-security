<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Free\Guide\Module;
use AmazingPlugins\Security\Free\Guide\Score;

/** Everything the last scan flagged, plus protections that are still off. */
final class StartPanel {
	public static function register(): void {
		add_submenu_page(
			Submenu::PARENT,
			__( 'Recommendations', 'amazingplugins-security-scanner' ),
			__( 'Recommendations', 'amazingplugins-security-scanner' ),
			'manage_options',
			'amsec-recommendations',
			array( self::class, 'render' )
		);
	}

	public static function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'amazingplugins-security-scanner' ), '', array( 'response' => 403 ) );
		}
		echo '<div class="wrap amazing-security-admin">';
		echo '<h1>' . esc_html__( 'Recommendations', 'amazingplugins-security-scanner' ) . '</h1>';
		( new AdminPage() )->recommendations();
		echo '</div>';
	}

	public static function incident(): void {
		echo '<section class="amsec-overview"><h2>' . esc_html__( 'If something looks wrong', 'amazingplugins-security-scanner' ) . '</h2><p>' . esc_html__( 'Review administrators, end other sessions, require a new password, then scan again.', 'amazingplugins-security-scanner' ) . ' <a class="button" href="' . esc_url( admin_url( 'admin.php?page=amsec-incident' ) ) . '">' . esc_html__( 'Open incident steps', 'amazingplugins-security-scanner' ) . '</a></p></section>';
	}

	/**
	 * Protections the scan does not list, still off.
	 *
	 * @return list<array<string, mixed>>
	 */
	public static function offRows(): array {
		$options = self::options();
		$off     = array();
		foreach ( Module::rows() as $row ) {
			$on = ! empty( $row['idle'] ) ? in_array( (string) $options['amsec_idle_minutes'], array( '15', '30', '60' ), true ) : '1' === (string) ( $options[ $row['key'] ] ?? '0' );
			// The scan list already offers the switches that live on the Scan page.
			if ( ! $on && 'amazing-security' !== $row['page'] ) {
				$off[] = $row;
			}
		}
		return $off;
	}

	/** @return array<string, mixed> */
	private static function options(): array {
		$options = array();
		foreach ( array_keys( Score::FLAGS ) as $key ) {
			$options[ $key ] = get_option( $key, '0' );
		}
		$options['amsec_idle_minutes'] = get_option( 'amsec_idle_minutes', '0' );
		return $options;
	}

	/** @param list<array<string, mixed>> $off From offRows(). */
	public static function protections( array $off ): void {
		$score = Score::tally( self::options() );
		echo '<section class="amsec-overview" aria-labelledby="amsec-rec-protections"><h2 id="amsec-rec-protections">' . esc_html( __( 'Protections that are off', 'amazingplugins-security-scanner' ) . ' (' . count( $off ) . ')' ) . '</h2>';
		echo '<p>' . esc_html(
			sprintf(
				/* translators: 1: protections on, 2: protections counted */
				__( '%1$d of %2$d protections are on. Each one stays off until you turn it on.', 'amazingplugins-security-scanner' ),
				$score['on'],
				$score['total']
			)
		) . ' <a href="' . esc_url( admin_url( 'admin.php?page=amsec-guide' ) ) . '">' . esc_html__( 'Apply a blog or shop preset', 'amazingplugins-security-scanner' ) . '</a></p>';
		if ( array() !== $off ) {
			echo '<ul class="amsec-start">';
			foreach ( $off as $row ) {
				echo '<li class="amsec-start-item" data-state="none"><span class="amsec-start-badge">' . esc_html__( 'Off', 'amazingplugins-security-scanner' ) . '</span><span class="amsec-start-copy"><strong>' . esc_html( $row['label'] ) . '</strong></span> <a class="button" href="' . esc_url( admin_url( 'admin.php?page=' . $row['page'] ) . ( isset( $row['hash'] ) ? '#' . $row['hash'] : '' ) ) . '">' . esc_html__( 'Turn on', 'amazingplugins-security-scanner' ) . '</a></li>';
			}
			echo '</ul>';
		}
		echo '</section>';
	}
}
