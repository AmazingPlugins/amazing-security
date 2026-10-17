<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Free\PasswordRules;

defined( 'ABSPATH' ) || exit;

/** Local password rules for a new or reset password. No WordPress calls. */
final class Decision {
	public const OPTION = 'amsec_password_min_length';

	public const NUMBER = 'amsec_password_require_number';

	public const MIXED = 'amsec_password_require_mixed';

	public const SYMBOL = 'amsec_password_require_symbol';

	public const NAME = 'amsec_password_block_name';

	public const REUSE = 'amsec_password_block_reuse';

	/** @var list<string> */
	public const ALLOWED = array( '8', '12', '16' );

	public static function normalize( string $stored ): string {
		return in_array( $stored, self::ALLOWED, true ) ? $stored : '0';
	}

	public static function minimum( string $stored ): int {
		$value = self::normalize( $stored );
		return '0' === $value ? 0 : (int) $value;
	}

	public static function enabled( string $stored ): bool {
		return '1' === $stored;
	}

	/**
	 * Reject a too-short new or reset password. Sign-in and any other moment are left alone.
	 */
	public static function rejects( string $stored, int $length, string $when ): bool {
		if ( 'new' !== $when && 'reset' !== $when ) {
			return false;
		}
		$minimum = self::minimum( $stored );
		if ( $minimum < 1 ) {
			return false;
		}
		return $length < $minimum;
	}

	/**
	 * First failed rule, or null when the password can be saved.
	 * Sign-in is never rejected. An empty password is not a change.
	 */
	public static function violation(
		string $when,
		string $password,
		string $min_stored,
		string $number,
		string $both_cases,
		string $symbol,
		string $block_name,
		string $block_reuse,
		string $username,
		string $email,
		bool $matches_current
	): ?string {
		if ( 'new' !== $when && 'reset' !== $when ) {
			return null;
		}
		if ( '' === $password ) {
			return null;
		}
		$minimum = self::minimum( $min_stored );
		if ( $minimum > 0 && self::length( $password ) < $minimum ) {
			return 'length';
		}
		if ( self::enabled( $number ) && ! self::hasNumber( $password ) ) {
			return 'number';
		}
		if ( self::enabled( $both_cases ) && ! self::hasMixed( $password ) ) {
			return 'mixed';
		}
		if ( self::enabled( $symbol ) && ! self::hasSymbol( $password ) ) {
			return 'symbol';
		}
		if ( self::enabled( $block_name ) && self::containsAccountName( $password, $username, $email ) ) {
			return 'name';
		}
		if ( self::enabled( $block_reuse ) && $matches_current ) {
			return 'reuse';
		}
		return null;
	}

	public static function length( string $password ): int {
		if ( function_exists( 'mb_strlen' ) ) {
			return mb_strlen( $password, 'UTF-8' );
		}
		return strlen( $password );
	}

	private static function hasNumber( string $password ): bool {
		return 1 === preg_match( '/\p{N}/u', $password );
	}

	private static function hasMixed( string $password ): bool {
		return 1 === preg_match( '/\p{Ll}/u', $password ) && 1 === preg_match( '/\p{Lu}/u', $password );
	}

	private static function hasSymbol( string $password ): bool {
		return 1 === preg_match( '/[^\p{L}\p{N}\s]/u', $password );
	}

	private static function containsAccountName( string $password, string $username, string $email ): bool {
		$haystack = self::lower( $password );
		foreach ( array( $username, self::emailName( $email ) ) as $needle ) {
			$needle = self::lower( trim( $needle ) );
			if ( self::length( $needle ) < 3 ) {
				continue;
			}
			if ( str_contains( $haystack, $needle ) ) {
				return true;
			}
		}
		return false;
	}

	private static function emailName( string $email ): string {
		$parts = explode( '@', $email, 2 );
		return $parts[0];
	}

	private static function lower( string $value ): string {
		if ( function_exists( 'mb_strtolower' ) ) {
			return mb_strtolower( $value, 'UTF-8' );
		}
		return strtolower( $value );
	}
}
