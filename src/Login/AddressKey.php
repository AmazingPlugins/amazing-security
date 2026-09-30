<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Login;

final class AddressKey {
	private readonly ?\Closure $resolver;
	public function __construct( private string $salt, ?callable $resolver = null ) {
		$this->resolver = null === $resolver ? null : \Closure::fromCallable( $resolver ); }

	public function fromServer( array $server ): ?string {
		try {
			$address = null === $this->resolver ? ( $server['REMOTE_ADDR'] ?? null ) : ( $this->resolver )( $server );
		} catch ( \Throwable ) {
			return null; }
		if ( ! is_string( $address ) || false === filter_var( $address, FILTER_VALIDATE_IP ) ) {
			return null;
		}
		$bytes = inet_pton( $address );
		return false === $bytes ? null : hash_hmac( 'sha256', $bytes, $this->salt );
	}
}
