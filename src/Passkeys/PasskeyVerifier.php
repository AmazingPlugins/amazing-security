<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Passkeys;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Vendor\WebAuthn\WebAuthn;

/** The only application bridge to the pinned signature verifier. */
final class PasskeyVerifier {
	public static function available(): bool {
		return PHP_INT_SIZE >= 8 && extension_loaded( 'openssl' ) && extension_loaded( 'mbstring' );
	}
	public function registration( string $payload, PasskeyContext $context, string $challenge ): ?array {
		if ( ! self::available() ) {
			return null; }
		$envelope = new PasskeyEnvelope();
		$data     = $envelope->read( $payload, true );
		if ( null === $data || ! $envelope->clientData( $data['client_data'], $context, true, $challenge ) ) {
			return null; }
		$profile = ( new AuthenticatorProfile() )->registration( $data['attestation'], $data['credential_id'] );
		if ( null === $profile ) {
			return null; }
		try {
			$verified = $this->upstream( $context )->processCreate( $data['client_data'], $data['attestation'], Base64Url::decode( $challenge, 32 ), true, true );
			if ( ! is_string( $verified->credentialPublicKey ) || ! $this->supportedKey( $verified->credentialPublicKey ) || ! hash_equals( $data['credential_id'], $verified->credentialId ) ) {
				return null; }
			return array(
				'credential_id'   => $data['credential_id'],
				'public_key'      => $verified->credentialPublicKey,
				'counter'         => $profile['counter'],
				'backup_eligible' => $profile['backup_eligible'],
				'backed_up'       => $profile['backed_up'],
			);
		} catch ( \Throwable $error ) {
			return null; }
	}
	public function assertion( string $payload, PasskeyContext $context, string $challenge, string $credentialId, string $userHandle, string $publicKey, int $previousCounter, bool $backupEligible ): ?array {
		if ( ! self::available() || $previousCounter < 0 || $previousCounter > 4294967295 || strlen( $userHandle ) !== 32 || ! $this->supportedKey( $publicKey ) ) {
			return null; }
		$envelope = new PasskeyEnvelope();
		$data     = $envelope->read( $payload, false );
		if ( null === $data || ! hash_equals( $credentialId, $data['credential_id'] ) || ! hash_equals( $userHandle, $data['user_handle'] ) || ! $envelope->clientData( $data['client_data'], $context, false, $challenge ) ) {
			return null; }
		$profile = ( new AuthenticatorProfile() )->assertion( $data['authenticator_data'] );
		if ( null === $profile || $profile['backup_eligible'] !== $backupEligible ) {
			return null; }
		try {
			$valid = $this->upstream( $context )->processGet( $data['client_data'], $data['authenticator_data'], $data['signature'], $publicKey, Base64Url::decode( $challenge, 32 ), $previousCounter, true, true );
			return true === $valid ? array(
				'counter'   => $profile['counter'],
				'backed_up' => $profile['backed_up'],
			) : null;
		} catch ( \Throwable $error ) {
			return null; }
	}
	public function supportedKey( string $pem ): bool {
		if ( strlen( $pem ) > 2048 || ! extension_loaded( 'openssl' ) || ! str_starts_with( $pem, '-----BEGIN PUBLIC KEY-----' ) ) {
			return false; }
		// Invalid stored/public coordinates must fail without emitting protocol material in warnings.
	 // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- OpenSSL rejects malformed public keys; no secret keys are processed here.
		$key = @openssl_pkey_get_public( $pem );
		if ( false === $key ) {
			return false; }
		$details = openssl_pkey_get_details( $key );
		return is_array( $details ) && OPENSSL_KEYTYPE_EC === $details['type'] && 256 === $details['bits'] && ( $details['ec']['curve_name'] ?? null ) === 'prime256v1';
	}
	private function upstream( PasskeyContext $context ): WebAuthn {
		return new WebAuthn( 'Amazing Security', $context->rpId(), array( 'none' ), true );
	}
}
