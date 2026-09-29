<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Login;

use InvalidArgumentException;

final class RecoveryCodes {
	public function generate( int $count = 10 ): array {
		if ( $count < 1 || $count > 10 ) {
			throw new InvalidArgumentException( 'Invalid recovery code count.' );
		}
		$codes = array();
		for ( $index = 0; $index < $count; ++$index ) {
			$codes[] = bin2hex( random_bytes( 12 ) );
		}
		return $codes;
	}

	public function hashAll( array $codes ): array {
		return array_map( static fn ( string $code ): string => password_hash( $code, PASSWORD_DEFAULT ), $codes );
	}
}
