<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Free\Guide;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Login\LoginFormFields;

final class Module {
	public static function boot(): void {
		add_action( 'admin_menu', array( self::class, 'menu' ) );
		add_action( 'admin_post_ironlatch_guide_preset', array( self::class, 'applyPreset' ) );
		add_action( 'woocommerce_login_form', array( self::class, 'wooLogin' ) );
		add_action( 'woocommerce_account_dashboard', array( self::class, 'wooAccount' ) );
		add_action( 'ironlatch_custom_login_form', array( self::class, 'customLogin' ) );
	}

	public static function menu(): void {
		add_submenu_page( 'ironlatch-security-scanner', __( 'Site review', 'ironlatch-security-scanner' ), __( 'Site review', 'ironlatch-security-scanner' ), 'manage_options', 'ironlatch-guide', array( self::class, 'render' ) );
	}

	public static function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'ironlatch-security-scanner' ), '', array( 'response' => 403 ) );
		}
		$options = array();
		foreach ( array_keys( Score::FLAGS ) as $key ) {
			$options[ $key ] = get_option( $key, '0' );
		}
		$options['ironlatch_idle_minutes'] = get_option( 'ironlatch_idle_minutes', '0' );
		$score                             = Score::tally( $options );
		echo '<div class="wrap ironlatch-security-scanner-admin"><h1>' . esc_html__( 'Site review', 'ironlatch-security-scanner' ) . '</h1>';
		echo '<p>' . esc_html(
			sprintf(
			/* translators: 1: number on, 2: number checked */
				__( '%1$d of %2$d local protections are on. This review does not mean the site is clean.', 'ironlatch-security-scanner' ),
				$score['on'],
				$score['total']
			)
		) . '</p>';
		echo '<ul class="ironlatch-start ironlatch-guide">';
		foreach ( self::rows() as $row ) {
			$on = ! empty( $row['idle'] )
				? in_array( (string) $options['ironlatch_idle_minutes'], array( '15', '30', '60' ), true )
				: (string) ( $options[ $row['key'] ] ?? '0' ) === '1';
			echo '<li class="ironlatch-start-item" data-state="' . esc_attr( $on ? 'pass' : 'none' ) . '"><span class="ironlatch-start-badge">' . esc_html( $on ? __( 'On', 'ironlatch-security-scanner' ) : __( 'Off', 'ironlatch-security-scanner' ) ) . '</span><span class="ironlatch-start-copy"><strong>' . esc_html( $row['label'] ) . '</strong></span>';
			echo '<a class="button" href="' . esc_url( admin_url( 'admin.php?page=' . $row['page'] ) . ( isset( $row['hash'] ) ? '#' . $row['hash'] : '' ) ) . '">' . esc_html__( 'Open', 'ironlatch-security-scanner' ) . '</a></li>';
		}
		echo '</ul>';
		echo '<p>' . esc_html__( 'A preset turns on local checks only. It does not start a breach lookup, a vulnerability lookup, or request blocking.', 'ironlatch-security-scanner' ) . '</p>';
		echo '<div class="ironlatch-file-actionbar">';
		foreach ( array( 'blog', 'shop' ) as $name ) {
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
			echo '<input type="hidden" name="action" value="ironlatch_guide_preset">';
			echo '<input type="hidden" name="preset" value="' . esc_attr( $name ) . '">';
			wp_nonce_field( 'ironlatch_guide_preset' );
			submit_button( 'blog' === $name ? __( 'Apply the blog preset', 'ironlatch-security-scanner' ) : __( 'Apply the shop preset', 'ironlatch-security-scanner' ), 'primary', 'submit', false );
			echo '</form>';
		}
		echo '</div>';
		echo '</div>';
	}

	/**
	 * @return list<array{key: string, label: string, page: string, hash?: string, idle?: bool}>
	 */
	public static function rows(): array {
		return array(
			array(
				'key'   => 'ironlatch_login_confirm',
				'label' => __( 'Login bot trap', 'ironlatch-security-scanner' ),
				'page'  => 'ironlatch-security-scanner',
			),
			array(
				'key'   => 'ironlatch_generic_login_errors',
				'label' => __( 'One login message', 'ironlatch-security-scanner' ),
				'page'  => 'ironlatch-security-scanner',
			),
			array(
				'key'   => 'ironlatch_hide_author_archives',
				'label' => __( 'Author pages closed', 'ironlatch-security-scanner' ),
				'page'  => 'ironlatch-security-scanner',
			),
			array(
				'key'   => 'ironlatch_hide_rest_users',
				'label' => __( 'Public user list closed', 'ironlatch-security-scanner' ),
				'page'  => 'ironlatch-security-scanner',
			),
			array(
				'key'   => 'ironlatch_hotlink',
				'label' => __( 'Hotlink check', 'ironlatch-security-scanner' ),
				'page'  => 'ironlatch-traffic-guard',
			),
			array(
				'key'   => 'ironlatch_approve_registrations',
				'label' => __( 'Registration approval', 'ironlatch-security-scanner' ),
				'page'  => 'ironlatch-accounts',
			),
			array(
				'key'   => 'ironlatch_email_factor',
				'label' => __( 'Email sign-in code', 'ironlatch-security-scanner' ),
				'page'  => 'ironlatch-accounts',
			),
			array(
				'key'   => 'ironlatch_login_challenge',
				'label' => __( 'Sign-in question', 'ironlatch-security-scanner' ),
				'page'  => 'ironlatch-accounts',
			),
			array(
				'key'   => 'ironlatch_idle_minutes',
				'label' => __( 'Idle logout', 'ironlatch-security-scanner' ),
				'page'  => 'ironlatch-accounts',
				'idle'  => true,
			),
		);
	}

	public static function applyPreset(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'ironlatch-security-scanner' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'ironlatch_guide_preset' );
		$name = isset( $_POST['preset'] ) && is_string( $_POST['preset'] ) ? sanitize_key( wp_unslash( $_POST['preset'] ) ) : '';
		foreach ( Score::preset( $name ) as $key => $value ) {
			update_option( $key, $value );
		}
		wp_safe_redirect( \AmazingPlugins\Security\Admin\Brand::saved( admin_url( 'admin.php?page=ironlatch-guide' ) ) );
		exit;
	}

	public static function wooLogin(): void {
		// Passkey login button retired.
	}

	public static function wooAccount(): void {
		echo '<p><a href="' . esc_url( admin_url( 'admin.php?page=ironlatch-accounts#passkeys' ) ) . '">' . esc_html__( 'Check passkey status', 'ironlatch-security-scanner' ) . '</a></p>';
	}

	public static function customLogin(): void {
		( new LoginFormFields() )->render();
	}
}
