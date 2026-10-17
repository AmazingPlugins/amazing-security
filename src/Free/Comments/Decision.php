<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Free\Comments;

defined( 'ABSPATH' ) || exit;

/** Accept or reject from the extra comment field. No WordPress calls. */
final class Decision {
	public const OPTION = 'amsec_comment_honeypot';
	public const FIELD  = 'amsec_comment_company';

	public static function flag( mixed $value ): string {
		return '1' === $value ? '1' : '0';
	}

	public static function text( mixed $value ): string {
		if ( ! is_string( $value ) ) {
			return 'filled';
		}
		return trim( $value );
	}

	public static function outcome( string $enabled, mixed $honeypot ): string {
		if ( '1' !== $enabled ) {
			return 'allow';
		}
		if ( '' === self::text( $honeypot ) ) {
			return 'allow';
		}
		return 'reject';
	}
}
