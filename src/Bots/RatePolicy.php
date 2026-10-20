<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Bots;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Network\Cidr;

/** Pure rules for guest rate limiting: settings bounds, request kinds, exemptions and the Watch/Block decision. */
final class RatePolicy {
	public const MODES     = array( 'off', 'watch', 'block' );
	public const MAX_ALLOW = 50;
	/** Field => [default, min, max]. Counts are per minute, block is in minutes. */
	public const BOUNDS = array(
		'page'  => array( 120, 30, 600 ),
		'rest'  => array( 60, 10, 300 ),
		'login' => array( 20, 5, 100 ),
		'block' => array( 10, 1, 60 ),
	);

	public static function defaults(): array {
		$out = array( 'mode' => 'off' );
		foreach ( self::BOUNDS as $field => $bound ) {
			$out[ $field ] = $bound[0];
		}
		return $out + array( 'allow' => array() );
	}

	/** Reads the stored option. Anything out of shape falls back to the default for that field. */
	public static function read( mixed $stored ): array {
		$out = self::defaults();
		if ( ! is_array( $stored ) ) {
			return $out;
		}
		if ( in_array( $stored['mode'] ?? null, self::MODES, true ) ) {
			$out['mode'] = $stored['mode'];
		}
		foreach ( self::BOUNDS as $field => $bound ) {
			$value = $stored[ $field ] ?? null;
			if ( is_int( $value ) && $value >= $bound[1] && $value <= $bound[2] ) {
				$out[ $field ] = $value;
			}
		}
		if ( is_array( $stored['allow'] ?? null ) ) {
			$out['allow'] = array_slice( array_values( array_filter( $stored['allow'], static fn( mixed $line ): bool => is_string( $line ) && null !== Cidr::canonical( $line ) ) ), 0, self::MAX_ALLOW );
		}
		return $out;
	}

	/**
	 * Validates raw form input.
	 *
	 * @return array{0: ?array, 1: array<string, mixed>} Settings, or null with errors: numbers => field names, lines => 1-based line numbers, too_many => true.
	 */
	public static function validate( array $input ): array {
		$out    = array();
		$errors = array();
		$mode   = $input['mode'] ?? null;
		if ( ! in_array( $mode, self::MODES, true ) ) {
			$errors['mode'] = true;
		}
		$out['mode'] = $mode;
		foreach ( self::BOUNDS as $field => $bound ) {
			$raw = $input[ $field ] ?? null;
			if ( ! is_string( $raw ) || 1 !== preg_match( '/^\d{1,4}$/D', trim( $raw ) ) || (int) $raw < $bound[1] || (int) $raw > $bound[2] ) {
				$errors['numbers'][] = $field;
				continue;
			}
			$out[ $field ] = (int) $raw;
		}
		$lines = is_string( $input['allow'] ?? null ) ? preg_split( '/\R/', $input['allow'] ) : array();
		$allow = array();
		foreach ( $lines as $n => $line ) {
			$line = trim( $line );
			if ( '' === $line ) {
				continue;
			}
			$canonical = Cidr::canonical( $line );
			if ( null === $canonical ) {
				$errors['lines'][] = $n + 1;
				continue;
			}
			$allow[] = str_contains( $line, '/' ) ? $canonical : explode( '/', $canonical )[0];
		}
		$allow = array_values( array_unique( $allow ) );
		if ( count( $allow ) > self::MAX_ALLOW ) {
			$errors['too_many'] = true;
		}
		$out['allow'] = $allow;
		return array() === $errors ? array( $out, array() ) : array( null, $errors );
	}

	/** Returns page, rest, xmlrpc or login. Only POSTs to wp-login.php and admin-ajax.php are login requests. */
	public static function classify( string $path, bool $restRoute, string $restPath, string $pagenow, string $method, bool $xmlrpc, bool $ajax ): string {
		if ( $xmlrpc || 'xmlrpc.php' === $pagenow ) {
			return 'xmlrpc';
		}
		if ( $restRoute || ( '' !== $restPath && str_starts_with( $path, $restPath ) ) ) {
			return 'rest';
		}
		if ( 'POST' === strtoupper( $method ) && ( $ajax || 'wp-login.php' === $pagenow ) ) {
			return 'login';
		}
		return 'page';
	}

	public static function limit( array $settings, string $kind ): int {
		return (int) $settings[ 'xmlrpc' === $kind ? 'rest' : $kind ];
	}

	public static function listed( string $address, array $allow ): bool {
		foreach ( $allow as $entry ) {
			if ( Cidr::contains( $entry, $address ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * A request from the server itself. Only when the client address is the direct peer: once a trusted
	 * proxy supplied a forwarded address, a loopback peer is the proxy, not the visitor.
	 */
	public static function fromServer( string $peer, string $client, string $serverAddr ): bool {
		if ( '' === $peer || $client !== $peer ) {
			return false;
		}
		return in_array( $peer, array( '127.0.0.1', '::1' ), true ) || ( '' !== $serverAddr && $peer === $serverAddr );
	}

	/** Returns none, flag or block for a count inside the current minute. */
	public static function decide( string $mode, ?int $count, int $limit ): string {
		if ( null === $count || $count <= $limit || ! in_array( $mode, array( 'watch', 'block' ), true ) ) {
			return 'none';
		}
		return 'block' === $mode ? 'block' : 'flag';
	}
}
