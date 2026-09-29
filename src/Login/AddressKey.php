<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Login;

final class AddressKey {
	public function __construct( private string $salt ) {}

	public function fromServer( array $server ): ?string {
		$address = $server['REMOTE_ADDR'] ?? null;
		if ( ! is_string( $address ) || false === filter_var( $address, FILTER_VALIDATE_IP ) ) {
			return null;
		}
		$bytes = inet_pton( $address );
		return false === $bytes ? null : hash_hmac( 'sha256', $bytes, $this->salt );
	}
}
