<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Free\Comments;

defined( 'ABSPATH' ) || exit;

/** Comment checks screen. Posts to admin-post.php. */
final class Page {
	public static function menu(): void {
		add_submenu_page(
			'ironlatch-security-scanner',
			__( 'Comment checks', 'ironlatch-security-scanner' ),
			__( 'Comment checks', 'ironlatch-security-scanner' ),
			'manage_options',
			'ironlatch-comments',
			array( self::class, 'render' )
		);
	}

	public static function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'ironlatch-security-scanner' ), '', array( 'response' => 403 ) );
		}
		$enabled = self::stored();
		$on      = '1' === $enabled;
		echo '<div class="wrap ironlatch-security-scanner-admin ironlatch-brief">';
		echo '<h1>' . esc_html__( 'Comment checks', 'ironlatch-security-scanner' ) . '</h1>';
		echo '<p class="ironlatch-brief-status"><span class="ironlatch-pill' . ( $on ? ' is-on' : ' is-off' ) . '">' . esc_html( $on ? __( 'On', 'ironlatch-security-scanner' ) : __( 'Off', 'ironlatch-security-scanner' ) ) . '</span>';
		echo esc_html( self::status( $enabled ) ) . '</p>';
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
		echo '<input type="hidden" name="action" value="ironlatch_comments_save">';
		wp_nonce_field( 'ironlatch_comments_save' );
		echo '<p class="ironlatch-check"><label><input type="checkbox" name="' . esc_attr( Decision::OPTION ) . '" value="1"' . checked( '1', $enabled, false ) . '> ';
		echo esc_html__( 'Add an extra field to the comment form', 'ironlatch-security-scanner' );
		echo '</label> ';
		self::tip( __( 'The field is named Company and sits off screen. Leave it empty. A filled field refuses the comment. Nothing is sent to another host.', 'ironlatch-security-scanner' ) );
		echo '</p>';
		echo '<p class="ironlatch-check"><label><input type="checkbox" name="' . esc_attr( Rate::OPTION ) . '" value="1"' . checked( '1', self::rateStored(), false ) . '> ';
		echo esc_html__( 'Wait one minute between comments from the same account or email', 'ironlatch-security-scanner' );
		echo '</label> ';
		self::tip( __( 'Administrators are not limited.', 'ironlatch-security-scanner' ) );
		echo '</p>';
		echo '<p class="ironlatch-check"><label><input type="checkbox" name="' . esc_attr( SpamHold::OPTION ) . '" value="1"' . checked( '1', self::holdStored(), false ) . '> ';
		echo esc_html__( 'Hold later comments from an email you marked as spam', 'ironlatch-security-scanner' );
		echo '</label> ';
		self::tip( __( 'The site stores a hash of that email, not the address.', 'ironlatch-security-scanner' ) );
		echo '</p>';
		submit_button( __( 'Save comment checks', 'ironlatch-security-scanner' ) );
		echo '</form>';
		echo '<details class="ironlatch-more"><summary>' . esc_html__( 'See more', 'ironlatch-security-scanner' ) . '</summary>';
		echo '<p>' . esc_html__( 'These start off. The extra field is for the WordPress comment form. A person leaves it empty. A filled field refuses the comment, and nothing is sent to another host.', 'ironlatch-security-scanner' ) . '</p>';
		echo '<p>' . esc_html__( 'The minute switch allows one comment per minute from the same account or email. Administrators are not limited. The hold switch keeps later comments from an email after you mark one as spam, and it stores a hash of that email.', 'ironlatch-security-scanner' ) . '</p>';
		echo '</details></div>';
	}

	private static function tip( string $text ): void {
		static $n = 0;
		++$n;
		$id = 'ironlatch-comment-tip-' . $n;
		echo '<span class="ironlatch-tip"><button type="button" class="ironlatch-tip-button" aria-describedby="' . esc_attr( $id ) . '">' . esc_html__( 'Details', 'ironlatch-security-scanner' ) . '</button>';
		echo '<span class="ironlatch-tip-bubble" id="' . esc_attr( $id ) . '" role="tooltip">' . esc_html( $text ) . '</span></span>';
	}

	public static function save(): void {
		if ( ! self::postRequest() ) {
			wp_die( esc_html__( 'Open the comment checks page and use the form.', 'ironlatch-security-scanner' ), '', array( 'response' => 405 ) );
		}
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'ironlatch-security-scanner' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'ironlatch_comments_save' );
		$flags = array();
		foreach ( array( Decision::OPTION, Rate::OPTION, SpamHold::OPTION ) as $key ) {
			$flags[ $key ] = isset( $_POST[ $key ] ) && is_string( $_POST[ $key ] ) ? sanitize_text_field( wp_unslash( $_POST[ $key ] ) ) : '0';
		}
		update_option( Decision::OPTION, Decision::flag( $flags[ Decision::OPTION ] ) );
		update_option( Rate::OPTION, Rate::flag( $flags[ Rate::OPTION ] ) );
		update_option( SpamHold::OPTION, SpamHold::flag( $flags[ SpamHold::OPTION ] ) );
		wp_safe_redirect( \AmazingPlugins\Security\Admin\Brand::saved( admin_url( 'admin.php?page=ironlatch-traffic-guard#bots' ) ) );
		exit;
	}

	public static function status( string $flag ): string {
		if ( '1' === $flag ) {
			return __( 'Comment checks are on.', 'ironlatch-security-scanner' );
		}
		return __( 'Comment checks are off.', 'ironlatch-security-scanner' );
	}

	private static function postRequest(): bool {
		$method = isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '';
		return 'post' === $method;
	}

	private static function holdStored(): string {
		$value = get_option( SpamHold::OPTION, '0' );
		return SpamHold::flag( is_string( $value ) ? $value : '0' );
	}

	private static function stored(): string {
		$value = get_option( Decision::OPTION, '0' );
		if ( ! is_string( $value ) ) {
			return '0';
		}
		return Decision::flag( $value );
	}

	private static function rateStored(): string {
		$value = get_option( Rate::OPTION, '0' );
		return Rate::flag( is_string( $value ) ? $value : '0' );
	}
}
