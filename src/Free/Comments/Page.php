<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Free\Comments;

defined( 'ABSPATH' ) || exit;

/** Comment checks screen. Posts to admin-post.php. */
final class Page {
	public static function menu(): void {
		add_submenu_page(
			'amazing-security',
			__( 'Comment checks', 'amazing-security' ),
			__( 'Comment checks', 'amazing-security' ),
			'manage_options',
			'amsec-comments',
			array( self::class, 'render' )
		);
	}

	public static function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'amazing-security' ), '', array( 'response' => 403 ) );
		}
		$enabled = self::stored();
		$on      = '1' === $enabled;
		echo '<div class="wrap amazing-security-admin amsec-brief">';
		echo '<h1>' . esc_html__( 'Comment checks', 'amazing-security' ) . '</h1>';
		echo '<p class="amsec-brief-status"><span class="amsec-pill' . ( $on ? ' is-on' : ' is-off' ) . '">' . esc_html( $on ? __( 'On', 'amazing-security' ) : __( 'Off', 'amazing-security' ) ) . '</span>';
		echo esc_html( self::status( $enabled ) ) . '</p>';
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
		echo '<input type="hidden" name="action" value="amsec_comments_save">';
		wp_nonce_field( 'amsec_comments_save' );
		echo '<p class="amsec-check"><label><input type="checkbox" name="' . esc_attr( Decision::OPTION ) . '" value="1"' . checked( '1', $enabled, false ) . '> ';
		echo esc_html__( 'Add an extra field to the comment form', 'amazing-security' );
		echo '</label> ';
		self::tip( __( 'The field is named Company and sits off screen. Leave it empty. A filled field refuses the comment. Nothing is sent to another host.', 'amazing-security' ) );
		echo '</p>';
		echo '<p class="amsec-check"><label><input type="checkbox" name="' . esc_attr( Rate::OPTION ) . '" value="1"' . checked( '1', self::rateStored(), false ) . '> ';
		echo esc_html__( 'Wait one minute between comments from the same account or email', 'amazing-security' );
		echo '</label> ';
		self::tip( __( 'Administrators are not limited.', 'amazing-security' ) );
		echo '</p>';
		echo '<p class="amsec-check"><label><input type="checkbox" name="' . esc_attr( SpamHold::OPTION ) . '" value="1"' . checked( '1', self::holdStored(), false ) . '> ';
		echo esc_html__( 'Hold later comments from an email you marked as spam', 'amazing-security' );
		echo '</label> ';
		self::tip( __( 'The site stores a hash of that email, not the address.', 'amazing-security' ) );
		echo '</p>';
		submit_button( __( 'Save comment checks', 'amazing-security' ) );
		echo '</form>';
		echo '<details class="amsec-more"><summary>' . esc_html__( 'See more', 'amazing-security' ) . '</summary>';
		echo '<p>' . esc_html__( 'These start off. The extra field is for the WordPress comment form. A person leaves it empty. A filled field refuses the comment, and nothing is sent to another host.', 'amazing-security' ) . '</p>';
		echo '<p>' . esc_html__( 'The minute switch allows one comment per minute from the same account or email. Administrators are not limited. The hold switch keeps later comments from an email after you mark one as spam, and it stores a hash of that email.', 'amazing-security' ) . '</p>';
		echo '</details></div>';
	}

	private static function tip( string $text ): void {
		static $n = 0;
		++$n;
		$id = 'amsec-comment-tip-' . $n;
		echo '<span class="amsec-tip"><button type="button" class="amsec-tip-button" aria-describedby="' . esc_attr( $id ) . '">' . esc_html__( 'Details', 'amazing-security' ) . '</button>';
		echo '<span class="amsec-tip-bubble" id="' . esc_attr( $id ) . '" role="tooltip">' . esc_html( $text ) . '</span></span>';
	}

	public static function save(): void {
		self::guard();
		update_option( Decision::OPTION, Decision::flag( self::posted( Decision::OPTION ) ) );
		update_option( Rate::OPTION, Rate::flag( self::posted( Rate::OPTION ) ) );
		update_option( SpamHold::OPTION, SpamHold::flag( self::posted( SpamHold::OPTION ) ) );
		wp_safe_redirect( admin_url( 'admin.php?page=amsec-comments' ) );
		exit;
	}

	public static function status( string $flag ): string {
		if ( '1' === $flag ) {
			return __( 'Comment checks are on.', 'amazing-security' );
		}
		return __( 'Comment checks are off.', 'amazing-security' );
	}

	private static function guard(): void {
		if ( ! self::postRequest() ) {
			wp_die( esc_html__( 'Open the comment checks page and use the form.', 'amazing-security' ), '', array( 'response' => 405 ) );
		}
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'amazing-security' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'amsec_comments_save' );
	}

	private static function postRequest(): bool {
		$method = isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '';
		return 'post' === $method;
	}

	private static function posted( string $key ): string {
		// Nonce is checked in guard() before this runs.
		$raw = isset( $_POST[ $key ] ) ? sanitize_text_field( wp_unslash( $_POST[ $key ] ) ) : '0'; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce checked in guard().
		return is_string( $raw ) ? $raw : '0';
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
