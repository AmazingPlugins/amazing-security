<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Login;

use RuntimeException;

final class SecretCipher {
	private string $key;

	public function __construct( string $siteSecret ) {
		$this->key = hash_hkdf( 'sha256', $siteSecret, 32, 'amsec-totp-v1' );
	}

	public function encrypt( string $plaintext ): string {
		if ( ! function_exists( 'openssl_encrypt' ) || strlen( $plaintext ) > 256 ) {
			throw new RuntimeException( 'TOTP encryption is unavailable.' );
		}
		$nonce      = random_bytes( 12 );
		$tag        = '';
		$ciphertext = openssl_encrypt( $plaintext, 'aes-256-gcm', $this->key, OPENSSL_RAW_DATA, $nonce, $tag, 'amsec-totp-v1', 16 );
		if ( false === $ciphertext ) {
			throw new RuntimeException( 'TOTP encryption failed.' );
		}
		// Binary authenticated ciphertext needs a text-safe storage envelope.
		// phpcs:ignore
		return 'v1:' . base64_encode( $nonce . $tag . $ciphertext );
	}

	public function decrypt( string $envelope ): ?string {
		if ( ! function_exists( 'openssl_decrypt' ) || ! str_starts_with( $envelope, 'v1:' ) || strlen( $envelope ) > 512 ) {
			return null;
		}
		// Decode only our versioned ciphertext envelope, never executable code.
		// phpcs:ignore
		$bytes = base64_decode( substr( $envelope, 3 ), true );
		if ( false === $bytes || strlen( $bytes ) < 28 ) {
			return null;
		}
		$plaintext = openssl_decrypt( substr( $bytes, 28 ), 'aes-256-gcm', $this->key, OPENSSL_RAW_DATA, substr( $bytes, 0, 12 ), substr( $bytes, 12, 16 ), 'amsec-totp-v1' );
		return false === $plaintext ? null : $plaintext;
	}
}
