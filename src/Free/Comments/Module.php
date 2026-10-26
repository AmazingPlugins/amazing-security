<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Free\Comments;

defined( 'ABSPATH' ) || exit;

/** Comment form extra field. Off until an administrator turns it on. */
final class Module {
	public static function boot(): void {
		add_option( Decision::OPTION, '0' );
		add_option( Rate::OPTION, '0' );
		add_option( SpamHold::OPTION, '0' );
		add_action( 'transition_comment_status', array( self::class, 'rememberSpam' ), 10, 3 );
		add_action( 'comment_form', array( self::class, 'field' ) );
		add_filter( 'pre_comment_approved', array( self::class, 'gate' ), 10, 2 );
		add_action( 'admin_menu', array( Page::class, 'menu' ) );
		add_action( 'admin_post_amsec_comments_save', array( Page::class, 'save' ) );
	}

	public static function field( mixed $post_id = null ): void {
		unset( $post_id );
		if ( '1' !== self::stored() ) {
			return;
		}
		echo '<p class="amsec-comment-check" style="position:absolute;left:-9999px" aria-hidden="true">';
		echo '<label>' . esc_html__( 'Company', 'amazingplugins-security-scanner' ) . ' ';
		echo '<input type="text" name="' . esc_attr( Decision::FIELD ) . '" value="" tabindex="-1" autocomplete="off">';
		echo '</label></p>';
	}

	/**
	 * Comments already let through in this request, keyed by subject, post and text. WordPress runs pre_comment_approved twice per comment
	 * (wp_allow_comment, then wp_new_comment), and the second pass must not count as another comment.
	 *
	 * @var array<string, true>
	 */
	private static array $allowed = array();

	/**
	 * preprocess_comment has to return the comment array. Returning WP_Error there
	 * makes wp_new_comment read that array and crash. pre_comment_approved is the
	 * filter WordPress returns to the comment form when the value is a WP_Error.
	 * The error data has to be a status code, or wp-comments-post.php exits with
	 * an empty page.
	 *
	 * The comment body is discarded. This does not look at user agent, country, or referrer.
	 */
	public static function gate( mixed $approved, mixed $commentdata ): mixed {
		$enabled = self::stored();
		$posted  = '1' === $enabled ? self::honeypot() : '';
		if ( 'reject' === Decision::outcome( $enabled, $posted ) ) {
			return new \WP_Error(
				'amsec_comment_honeypot',
				__( 'Leave the extra field empty.', 'amazingplugins-security-scanner' ),
				403
			);
		}
		$rate    = self::rateStored();
		$exempt  = self::exempt();
		$subject = self::subject( $commentdata );
		$once    = self::fingerprint( $subject, $commentdata );
		$last    = isset( self::$allowed[ $once ] ) ? null : self::last( $subject );
		if ( 'wait' === Rate::decide( $rate, $exempt, $last, time() ) ) {
			return new \WP_Error(
				'amsec_comment_rate',
				__( 'Wait a minute before another comment.', 'amazingplugins-security-scanner' ),
				403
			);
		}
		if ( '1' === $rate && ! $exempt && '' !== $subject && function_exists( 'set_transient' ) ) {
			set_transient( self::transient( $subject ), (string) time(), Rate::GAP );
			self::$allowed[ $once ] = true;
		}
		$email = self::email( $commentdata );
		$hash  = SpamHold::digest( $email, function_exists( 'wp_salt' ) ? (string) wp_salt( 'auth' ) : '' );
		$list  = get_option( SpamHold::LIST, array() );
		if ( 'hold' === SpamHold::decide( self::holdStored(), $exempt, $hash, is_array( $list ) ? $list : array() ) ) {
			return new \WP_Error(
				'amsec_comment_spam_hold',
				__( 'This email is held after a spam comment.', 'amazingplugins-security-scanner' ),
				403
			);
		}
		return $approved;
	}

	public static function rememberSpam( string $status, string $old, mixed $comment ): void {
		if ( '1' !== self::holdStored() || 'spam' !== $status || 'spam' === $old || ! is_object( $comment ) ) {
			return;
		}
		$email  = isset( $comment->comment_author_email ) && is_string( $comment->comment_author_email ) ? $comment->comment_author_email : '';
		$hash   = SpamHold::digest( $email, function_exists( 'wp_salt' ) ? (string) wp_salt( 'auth' ) : '' );
		$list   = get_option( SpamHold::LIST, array() );
		$stored = is_array( $list ) ? $list : array();
		$next   = SpamHold::remember( $stored, $hash );
		if ( $stored !== $next ) {
			update_option( SpamHold::LIST, $next, false );
		}
	}

	private static function stored(): string {
		$value = get_option( Decision::OPTION, '0' );
		if ( ! is_string( $value ) ) {
			return '0';
		}
		return Decision::flag( $value );
	}

	private static function honeypot(): mixed {
		// Public comment field. Guests have no admin nonce, and the value is not stored.
		$raw = isset( $_POST[ Decision::FIELD ] ) ? wp_unslash( $_POST[ Decision::FIELD ] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		if ( ! is_string( $raw ) ) {
			return $raw;
		}
		return wp_unslash( $raw );
	}

	private static function rateStored(): string {
		$value = get_option( Rate::OPTION, '0' );
		return Rate::flag( is_string( $value ) ? $value : '0' );
	}

	private static function holdStored(): string {
		$value = get_option( SpamHold::OPTION, '0' );
		return SpamHold::flag( is_string( $value ) ? $value : '0' );
	}

	private static function email( mixed $commentdata ): string {
		if ( ! is_array( $commentdata ) ) {
			return '';
		}
		$email = $commentdata['comment_author_email'] ?? '';
		return is_string( $email ) ? $email : '';
	}

	private static function exempt(): bool {
		return function_exists( 'current_user_can' ) && current_user_can( 'manage_options' );
	}

	private static function subject( mixed $commentdata ): string {
		if ( ! is_array( $commentdata ) ) {
			return '';
		}
		$user_id = $commentdata['user_id'] ?? $commentdata['user_ID'] ?? 0;
		$email   = $commentdata['comment_author_email'] ?? '';
		return Rate::subject( is_numeric( $user_id ) ? (int) $user_id : 0, is_string( $email ) ? $email : '' );
	}

	/** One comment's identity, so only its own second pass is let through, not another comment from the same person. */
	private static function fingerprint( string $subject, mixed $commentdata ): string {
		$post = is_array( $commentdata ) && is_numeric( $commentdata['comment_post_ID'] ?? null ) ? (int) $commentdata['comment_post_ID'] : 0;
		$text = is_array( $commentdata ) && is_string( $commentdata['comment_content'] ?? null ) ? $commentdata['comment_content'] : '';
		return hash( 'sha256', $subject . "\0" . $post . "\0" . $text );
	}

	private static function last( string $subject ): ?int {
		if ( '' === $subject || ! function_exists( 'get_transient' ) ) {
			return null;
		}
		$stored = get_transient( self::transient( $subject ) );
		if ( is_int( $stored ) && $stored > 0 ) {
			return $stored;
		}
		if ( is_string( $stored ) && 1 === preg_match( '/\A[1-9]\d*\z/', $stored ) ) {
			return (int) $stored;
		}
		return null;
	}

	private static function transient( string $subject ): string {
		return 'amsec_cr_' . substr( hash( 'sha256', $subject ), 0, 32 );
	}
}
