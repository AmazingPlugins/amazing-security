<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Passkeys;

final class Base64Url {
	public static function encode( string $bytes ): string {
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- Canonical WebAuthn binary transport encoding.
		return rtrim( strtr( base64_encode( $bytes ), '+/', '-_' ), '=' ); }
	public static function decode( mixed $encoded, int $maximum ): ?string {
		if ( $maximum < 0 || $maximum > 98304 || ! is_string( $encoded ) || strlen( $encoded ) > intdiv( $maximum * 4 + 2, 3 ) || 1 === strlen( $encoded ) % 4 || 1 !== preg_match( '/^[a-zA-Z0-9_-]*$/D', $encoded ) ) {
			return null; }
	 // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- Protocol binary field decoding with strict canonical re-encoding and length bounds.
		$bytes = base64_decode( strtr( $encoded, '-_', '+/' ) . str_repeat( '=', ( 4 - strlen( $encoded ) % 4 ) % 4 ), true );
		return is_string( $bytes ) && strlen( $bytes ) <= $maximum && self::encode( $bytes ) === $encoded ? $bytes : null;
	}
}
