<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Free\Comments;

/** Holds a later comment from an email that was already marked spam. No visitor address. */
final class SpamHold {
	public const OPTION = 'amsec_comment_spam_hold';

	public const LIST = 'amsec_comment_spam_hashes';

	public static function flag( mixed $value ): string {
		return '1' === $value ? '1' : '0';
	}

	public static function digest( string $email, string $salt ): string {
		$email = strtolower( trim( $email ) );
		if ( '' === $salt || strlen( $email ) > 200 || ! str_contains( $email, '@' ) ) {
			return '';
		}
		return hash( 'sha256', $salt . "\0" . $email );
	}

	/**
	 * @param list<mixed> $hashes
	 * @return list<string>
	 */
	public static function remember( array $hashes, string $hash ): array {
		$clean = array();
		foreach ( $hashes as $item ) {
			if ( is_string( $item ) && 64 === strlen( $item ) && ctype_xdigit( $item ) ) {
				$clean[] = strtolower( $item );
			}
		}
		if ( '' === $hash || in_array( $hash, $clean, true ) ) {
			return $clean;
		}
		array_unshift( $clean, $hash );
		return array_slice( $clean, 0, 50 );
	}

	/**
	 * @param list<mixed> $hashes
	 */
	public static function decide( string $enabled, bool $exempt, string $hash, array $hashes ): string {
		if ( '1' !== $enabled || $exempt || '' === $hash ) {
			return 'allow';
		}
		foreach ( $hashes as $item ) {
			if ( is_string( $item ) && strlen( $item ) === strlen( $hash ) && hash_equals( strtolower( $item ), strtolower( $hash ) ) ) {
				return 'hold';
			}
		}
		return 'allow';
	}
}
