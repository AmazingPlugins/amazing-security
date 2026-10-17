<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Login;

defined( 'ABSPATH' ) || exit;

final class Totp {
	public function verify( string $secret, string $code, int $now, ?int $lastStep ): ?int {
		if ( strlen( $secret ) < 16 || ! preg_match( '/\A[0-9]{6}\z/', $code ) || $now < 0 ) {
			return null;
		}
		$step = intdiv( $now, 30 );
		foreach ( array( $step - 1, $step, $step + 1 ) as $candidate ) {
			if ( $candidate >= 0 && $candidate > ( $lastStep ?? -1 ) && hash_equals( $this->atStep( $secret, $candidate ), $code ) ) {
				return $candidate;
			}
		}
		return null;
	}

	public function atStep( string $secret, int $step ): string {
		$counter = pack( 'N2', intdiv( $step, 4294967296 ), $step % 4294967296 );
		$digest  = hash_hmac( 'sha1', $counter, $secret, true );
		$offset  = ord( $digest[19] ) & 15;
		$number  = unpack( 'N', substr( $digest, $offset, 4 ) )[1] & 0x7fffffff;
		return str_pad( (string) ( $number % 1000000 ), 6, '0', STR_PAD_LEFT );
	}

	public function generateSecret(): string {
		return random_bytes( 20 );
	}

	public function base32( string $bytes ): string {
		$alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
		$buffer   = 0;
		$bits     = 0;
		$result   = '';
		foreach ( unpack( 'C*', $bytes ) as $byte ) {
			$buffer = ( $buffer << 8 ) | $byte;
			$bits  += 8;
			while ( $bits >= 5 ) {
				$bits   -= 5;
				$result .= $alphabet[ ( $buffer >> $bits ) & 31 ];
			}
		}
		if ( $bits > 0 ) {
			$result .= $alphabet[ ( $buffer << ( 5 - $bits ) ) & 31 ];
		}
		return $result;
	}
}
