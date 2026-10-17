<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Passkeys;

defined( 'ABSPATH' ) || exit;

/** Shared type/budget guards for plugin-owned passkey records. */
final class PasskeyState {
	public static function object( mixed $raw, int $maximum, array $keys ): ?array {
		if ( ! is_string( $raw ) || strlen( $raw ) > $maximum ) {
			return null; }
		try {
		 // phpcs:ignore WordPress.WP.AlternativeFunctions.json_decode_json_decode -- Pure bounded plugin-owned record with exact typed keys.
			$value = json_decode( $raw, true, 8, JSON_THROW_ON_ERROR );
		} catch ( \JsonException ) {
			return null; }
		return is_array( $value ) && array_keys( $value ) === $keys ? $value : null;
	}
	public static function hex( mixed $value, int $length ): bool {
		return is_string( $value ) && strlen( $value ) === $length && 1 === preg_match( '/^[a-f0-9]+$/D', $value );
	}
	public static function integer( mixed $value, int $minimum, int $maximum ): bool {
		return is_int( $value ) && $value >= $minimum && $value <= $maximum;
	}
}
