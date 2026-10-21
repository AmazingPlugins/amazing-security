<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Login;

defined( 'ABSPATH' ) || exit;

final class AddressKey {
	private readonly ?\Closure $resolver;
	/** $prefix64 groups IPv6 clients by their /64, so rotating addresses inside one allocation counts as one. */
	public function __construct( private string $salt, ?callable $resolver = null, private bool $prefix64 = false ) {
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
		if ( false === $bytes ) {
			return null;
		}
		// An IPv4 address carried inside IPv6 (::ffff:a.b.c.d) is still that IPv4 address, so it must not share one /64 with every other.
		if ( 16 === strlen( $bytes ) && "\0\0\0\0\0\0\0\0\0\0\xff\xff" === substr( $bytes, 0, 12 ) ) {
			$bytes = substr( $bytes, 12 );
		}
		return hash_hmac( 'sha256', $this->prefix64 && 16 === strlen( $bytes ) ? substr( $bytes, 0, 8 ) : $bytes, $this->salt );
	}
}
