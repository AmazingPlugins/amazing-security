<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

defined( 'ABSPATH' ) || exit;

/** A category of settings. Each row opens that screen. */
final class SettingList {
	/**
	 * @param list<array{label: string, note: string, url: string}> $rows
	 */
	public static function render( string $title, string $intro, array $rows ): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'amazing-security' ), '', array( 'response' => 403 ) );
		}
		echo '<div class="wrap amazing-security-admin"><h1>' . esc_html( $title ) . '</h1>';
		echo '<p>' . esc_html( $intro ) . '</p><ul class="amsec-settings">';
		foreach ( $rows as $row ) {
			echo '<li><a href="' . esc_url( $row['url'] ) . '"><span class="amsec-settings-copy"><strong>' . esc_html( $row['label'] ) . '</strong><span>' . esc_html( $row['note'] ) . '</span></span><span class="amsec-settings-go">' . esc_html__( 'Open', 'amazing-security' ) . '</span></a></li>';
		}
		echo '</ul></div>';
	}

	public static function page( string $slug ): string {
		return admin_url( 'admin.php?page=' . $slug );
	}
}
