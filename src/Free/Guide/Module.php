<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Free\Guide;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Login\LoginFormFields;

final class Module {
	public static function boot(): void {
		add_action( 'admin_menu', array( self::class, 'menu' ) );
		add_action( 'admin_post_amsec_guide_preset', array( self::class, 'applyPreset' ) );
		add_action( 'woocommerce_login_form', array( self::class, 'wooLogin' ) );
		add_action( 'woocommerce_account_dashboard', array( self::class, 'wooAccount' ) );
		add_action( 'amsec_custom_login_form', array( self::class, 'customLogin' ) );
	}

	public static function menu(): void {
		add_submenu_page( 'amazing-security', __( 'Site review', 'amazing-security' ), __( 'Site review', 'amazing-security' ), 'manage_options', 'amsec-guide', array( self::class, 'render' ) );
	}

	public static function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'amazing-security' ), '', array( 'response' => 403 ) );
		}
		$options = array();
		foreach ( array_keys( Score::FLAGS ) as $key ) {
			$options[ $key ] = get_option( $key, '0' );
		}
		$options['amsec_idle_minutes'] = get_option( 'amsec_idle_minutes', '0' );
		$score                         = Score::tally( $options );
		echo '<div class="wrap amazing-security-admin"><h1>' . esc_html__( 'Site review', 'amazing-security' ) . '</h1>';
		echo '<p>' . esc_html(
			sprintf(
			/* translators: 1: number on, 2: number checked */
				__( '%1$d of %2$d local protections are on. This review does not mean the site is clean.', 'amazing-security' ),
				$score['on'],
				$score['total']
			)
		) . '</p>';
		echo '<ul class="amsec-start">';
		foreach ( self::rows() as $row ) {
			$on = ! empty( $row['idle'] )
				? in_array( (string) $options['amsec_idle_minutes'], array( '15', '30', '60' ), true )
				: (string) ( $options[ $row['key'] ] ?? '0' ) === '1';
			echo '<li class="amsec-start-item" data-state="' . esc_attr( $on ? 'pass' : 'none' ) . '"><span class="amsec-start-badge">' . esc_html( $on ? __( 'On', 'amazing-security' ) : __( 'Off', 'amazing-security' ) ) . '</span><span class="amsec-start-copy"><strong>' . esc_html( $row['label'] ) . '</strong></span>';
			echo '<a class="button" href="' . esc_url( admin_url( 'admin.php?page=' . $row['page'] ) ) . '">' . esc_html__( 'Open', 'amazing-security' ) . '</a></li>';
		}
		echo '</ul>';
		echo '<p>' . esc_html__( 'A preset turns on local checks only. It does not start a breach lookup, a vulnerability lookup, or request blocking.', 'amazing-security' ) . '</p>';
		foreach ( array( 'blog', 'shop' ) as $name ) {
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
			echo '<input type="hidden" name="action" value="amsec_guide_preset">';
			echo '<input type="hidden" name="preset" value="' . esc_attr( $name ) . '">';
			wp_nonce_field( 'amsec_guide_preset_' . $name );
			submit_button( 'blog' === $name ? __( 'Apply the blog preset', 'amazing-security' ) : __( 'Apply the shop preset', 'amazing-security' ) );
			echo '</form>';
		}
		echo '</div>';
	}

	/**
	 * @return list<array{key: string, label: string, page: string, idle?: bool}>
	 */
	private static function rows(): array {
		return array(
			array(
				'key'   => 'amsec_login_confirm',
				'label' => __( 'Sign-in confirmation', 'amazing-security' ),
				'page'  => 'amazing-security',
			),
			array(
				'key'   => 'amsec_generic_login_errors',
				'label' => __( 'One login message', 'amazing-security' ),
				'page'  => 'amazing-security',
			),
			array(
				'key'   => 'amsec_hide_author_archives',
				'label' => __( 'Author pages closed', 'amazing-security' ),
				'page'  => 'amazing-security',
			),
			array(
				'key'   => 'amsec_hide_rest_users',
				'label' => __( 'Public user list closed', 'amazing-security' ),
				'page'  => 'amazing-security',
			),
			array(
				'key'   => 'amsec_hotlink',
				'label' => __( 'Hotlink check', 'amazing-security' ),
				'page'  => 'amsec-traffic-guard',
			),
			array(
				'key'   => 'amsec_approve_registrations',
				'label' => __( 'Registration approval', 'amazing-security' ),
				'page'  => 'amsec-accounts',
			),
			array(
				'key'   => 'amsec_email_factor',
				'label' => __( 'Email sign-in code', 'amazing-security' ),
				'page'  => 'amsec-accounts',
			),
			array(
				'key'   => 'amsec_login_challenge',
				'label' => __( 'Sign-in question', 'amazing-security' ),
				'page'  => 'amsec-accounts',
			),
			array(
				'key'   => 'amsec_idle_minutes',
				'label' => __( 'Idle logout', 'amazing-security' ),
				'page'  => 'amsec-accounts',
				'idle'  => true,
			),
		);
	}

	public static function applyPreset(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'amazing-security' ), '', array( 'response' => 403 ) );
		}
		$name = isset( $_POST['preset'] ) ? sanitize_text_field( wp_unslash( (string) $_POST['preset'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- The nonce is checked on the next line for this preset name.
		check_admin_referer( 'amsec_guide_preset_' . $name );
		foreach ( Score::preset( $name ) as $key => $value ) {
			update_option( $key, $value );
		}
		wp_safe_redirect( admin_url( 'admin.php?page=amsec-guide' ) );
		exit;
	}

	public static function wooLogin(): void {
		// Passkey login button retired.
	}

	public static function wooAccount(): void {
		echo '<p><a href="' . esc_url( admin_url( 'admin.php?page=amsec-accounts#passkeys' ) ) . '">' . esc_html__( 'Check passkey status', 'amazing-security' ) . '</a></p>';
	}

	public static function customLogin(): void {
		( new LoginFormFields() )->render();
	}
}
