<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Free\Comments;

defined( 'ABSPATH' ) || exit;

/** One comment per minute for the same account or email. No WordPress calls. */
final class Rate {
	public const OPTION = 'amsec_comment_rate';

	public const GAP = 60;

	public static function flag( mixed $value ): string {
		return '1' === $value ? '1' : '0';
	}

	/**
	 * Logged-in comments use the account id. Guests use the email on the comment.
	 * An empty result means the comment is not limited.
	 */
	public static function subject( int $user_id, string $email ): string {
		if ( $user_id > 0 ) {
			return 'u' . $user_id;
		}
		$email = strtolower( trim( $email ) );
		if ( ! str_contains( $email, '@' ) ) {
			return '';
		}
		return 'e' . $email;
	}

	public static function decide( string $enabled, bool $exempt, ?int $last, int $now ): string {
		if ( '1' !== $enabled || $exempt ) {
			return 'allow';
		}
		if ( null === $last || $last < 1 ) {
			return 'allow';
		}
		if ( ( $now - $last ) < self::GAP ) {
			return 'wait';
		}
		return 'allow';
	}
}
