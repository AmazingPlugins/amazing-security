<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Free\Accounts;

defined( 'ABSPATH' ) || exit;

/** Email code checks. The stored record keeps a hash, never the code. */
final class EmailFactor {
	public const OPTION   = 'amsec_email_factor';
	public const META     = 'amsec_email_factor_pending';
	public const TTL      = 600;
	public const INTERVAL = 60;
	public const TRIES    = 5;

	public static function code(): string {
		return str_pad( (string) random_int( 0, 999999 ), 6, '0', STR_PAD_LEFT );
	}

	public static function hashCode( string $code, string $key ): string {
		return hash_hmac( 'sha256', $code, $key );
	}

	public static function enrolled( mixed $seed, mixed $stored ): bool {
		return self::present( $seed ) || self::present( $stored );
	}

	public static function present( mixed $value ): bool {
		if ( is_string( $value ) ) {
			return '' !== $value;
		}
		return is_array( $value ) && array() !== $value;
	}

	/**
	 * @return array{hash: string, expires: int, sent: int, tries: int}
	 */
	public static function record( string $code, int $now, string $key ): array {
		return array(
			'hash'    => self::hashCode( $code, $key ),
			'expires' => $now + self::TTL,
			'sent'    => $now,
			'tries'   => 0,
		);
	}

	/**
	 * Counts one wrong code. The record keeps its send time, so a burned code still waits out INTERVAL.
	 *
	 * @param array{hash: string, expires: int, sent: int, tries?: int} $stored
	 * @return array{hash: string, expires: int, sent: int, tries: int}
	 */
	public static function failedTry( array $stored ): array {
		$stored['tries'] = min( self::TRIES, (int) ( $stored['tries'] ?? 0 ) + 1 );
		return $stored;
	}

	/**
	 * @return array{hash: string, expires: int, sent: int, tries: int}|null
	 */
	public static function unpack( mixed $raw ): ?array {
		if ( ! is_string( $raw ) || '' === $raw ) {
			return null;
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.json_decode_json_decode -- Local user-meta record only. No request is made.
		$decoded = json_decode( $raw, true );
		if ( ! is_array( $decoded ) || ! isset( $decoded['hash'], $decoded['expires'], $decoded['sent'] ) ) {
			return null;
		}
		$hash = $decoded['hash'];
		if ( ! is_string( $hash ) || 1 !== preg_match( '/\A[a-f0-9]{64}\z/', $hash ) ) {
			return null;
		}
		return array(
			'hash'    => $hash,
			'expires' => (int) $decoded['expires'],
			'sent'    => (int) $decoded['sent'],
			'tries'   => (int) ( $decoded['tries'] ?? 0 ),
		);
	}

	/**
	 * Skip, accept, reject, or send. Send is rate limited to one code per minute.
	 *
	 * @param array{hash?: string, expires?: int, sent?: int, tries?: int}|null $stored
	 */
	public static function decision( bool $enabled, bool $hasTotp, bool $api, string $password, bool $authenticated, string $postedCode, ?array $stored, int $now, string $key ): string {
		if ( ! $enabled || $hasTotp || $api || ! $authenticated || '' === $password ) {
			return 'skip';
		}
		$posted = trim( $postedCode );
		if ( 1 === preg_match( '/\A\d{6}\z/', $posted ) && self::matches( $posted, $stored, $now, $key ) ) {
			return 'accept';
		}
		if ( '' !== $posted ) {
			return 'reject';
		}
		$sent = isset( $stored['sent'] ) ? (int) $stored['sent'] : 0;
		if ( $sent > 0 && ( $now - $sent ) < self::INTERVAL ) {
			return 'reject';
		}
		return 'send';
	}

	/**
	 * @param array{hash?: string, expires?: int, sent?: int, tries?: int}|null $stored
	 */
	public static function matches( string $posted, ?array $stored, int $now, string $key ): bool {
		if ( '' === $posted || ! is_array( $stored ) ) {
			return false;
		}
		$hash    = $stored['hash'] ?? '';
		$expires = $stored['expires'] ?? 0;
		if ( ! is_string( $hash ) || '' === $hash || $now > (int) $expires || (int) ( $stored['tries'] ?? 0 ) >= self::TRIES ) {
			return false;
		}
		return hash_equals( $hash, self::hashCode( $posted, $key ) );
	}
}
