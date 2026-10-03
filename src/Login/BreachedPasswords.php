<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Login;

/** Have I Been Pwned range check. It sends a hash prefix, not the password. */
final class BreachedPasswords {
	public static function matchesSuffix( string $suffix, string $body ): bool {
		$suffix = strtoupper( $suffix );
		if ( 1 !== preg_match( '/^[A-F0-9]{35}$/D', $suffix ) ) {
			return false;
		}
		$lines = preg_split( "/\r\n|\n|\r/", $body );
		if ( ! is_array( $lines ) ) {
			return false;
		}
		foreach ( $lines as $line ) {
			$parts = explode( ':', strtoupper( trim( $line ) ), 2 );
			if ( isset( $parts[0] ) && hash_equals( $suffix, $parts[0] ) ) {
				return true;
			}
		}
		return false;
	}

	public static function listed( string $password ): bool {
		if ( '' === $password ) {
			return false;
		}
		// Have I Been Pwned range lookup is defined as SHA-1.
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.PHP.DiscouragedPHPFunctions.sha1_sha1
		$hash   = strtoupper( sha1( $password ) );
		$prefix = substr( $hash, 0, 5 );
		if ( 1 !== preg_match( '/^[A-F0-9]{5}$/D', $prefix ) ) {
			return false;
		}
		$response = wp_remote_get(
			'https://api.pwnedpasswords.com/range/' . $prefix,
			array(
				'timeout'     => 2,
				'redirection' => 0,
				'user-agent'  => 'Amazing-Security',
				'headers'     => array( 'Add-Padding' => 'true' ),
			)
		);
		if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
			return false;
		}
		$body = wp_remote_retrieve_body( $response );
		return is_string( $body ) && strlen( $body ) <= 1048576 && self::matchesSuffix( substr( $hash, 5 ), $body );
	}
}
