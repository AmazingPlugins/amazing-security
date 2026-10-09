<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Free\Accounts;

/** On-site addition question. It does not call another host. */
final class LoginChallenge {
	public const OPTION           = 'amsec_login_challenge';
	public const COOKIE           = 'amsec_login_challenge';
	public const SUM              = 'amsec_login_sum';
	public const HONEYPOT         = 'amsec_login_company';
	public const TRANSIENT_PREFIX = 'amsec_lc_';

	public static function validToken( string $token ): bool {
		return 1 === preg_match( '/\A[a-f0-9]{32}\z/', $token );
	}

	public static function transientKey( string $token ): string {
		return self::TRANSIENT_PREFIX . $token;
	}

	/**
	 * @return array{left: int, right: int, sum: int}|null
	 */
	public static function pair( int $left, int $right ): ?array {
		if ( $left < 2 || $left > 9 || $right < 2 || $right > 9 ) {
			return null;
		}
		return array(
			'left'  => $left,
			'right' => $right,
			'sum'   => $left + $right,
		);
	}

	/**
	 * Wrong sum, missing token, or a filled honeypot rejects. This is separate from the password result.
	 */
	public static function decision( bool $enabled, bool $xmlRpc, bool $application, string $token, ?string $expected, string $postedSum, string $honeypot ): string {
		if ( ! $enabled || $xmlRpc || $application ) {
			return 'allow';
		}
		if ( '' !== $honeypot || ! self::validToken( $token ) || null === $expected || '' === $expected ) {
			return 'reject';
		}
		$posted = trim( $postedSum );
		if ( ! hash_equals( $expected, $posted ) ) {
			return 'reject';
		}
		return 'allow';
	}
}
