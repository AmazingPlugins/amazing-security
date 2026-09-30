<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Passkeys;

final class PasskeyEnvelope {
	public function read( string $json, bool $registration ): ?array {
		if ( strlen( $json ) > 98304 ) {
			return null; }
		try {
		 // phpcs:ignore WordPress.WP.AlternativeFunctions.json_decode_json_decode -- Pure bounded typed protocol envelope.
			$p = json_decode( $json, true, 16, JSON_THROW_ON_ERROR );
		} catch ( \JsonException ) {
			return null; }
		if ( ! is_array( $p ) || ! $this->keys( $p, array( 'id', 'rawId', 'type', 'response' ) ) || ! is_string( $p['id'] ) || $p['id'] !== $p['rawId'] || 'public-key' !== $p['type'] || ! is_array( $p['response'] ) ) {
			return null; }
		$id = Base64Url::decode( $p['id'], 1024 );
		if ( null === $id || '' === $id ) {
			return null; }
		$response = $p['response'];
		$fields   = $registration ? array(
			'clientDataJSON'    => array( 'client_data', 8192 ),
			'attestationObject' => array( 'attestation', 32768 ),
		) : array(
			'clientDataJSON'    => array( 'client_data', 8192 ),
			'authenticatorData' => array( 'authenticator_data', 8192 ),
			'signature'         => array( 'signature', 256 ),
			'userHandle'        => array( 'user_handle', 32 ),
		);
		if ( ! $this->keys( $response, array_keys( $fields ) ) ) {
			return null; }
		$decoded = array( 'credential_id' => $id );
		foreach ( $fields as $name => $field ) {
			$bytes = Base64Url::decode( $response[ $name ], $field[1] );
			if ( null === $bytes || '' === $bytes ) {
					return null;
			}$decoded[ $field[0] ] = $bytes; }
		if ( ! $registration && strlen( $decoded['user_handle'] ) !== 32 ) {
			return null; }
		return $decoded;
	}
	public function clientData( string $json, PasskeyContext $context, bool $registration, string $challenge ): bool {
		if ( strlen( $json ) > 8192 || strlen( $challenge ) > 128 || 32 !== strlen( Base64Url::decode( $challenge, 32 ) ?? '' ) ) {
			return false; }
		try {
		 // phpcs:ignore WordPress.WP.AlternativeFunctions.json_decode_json_decode -- Signed client data is inspected before upstream verification; the same original bytes are hashed by the verifier.
			$s = json_decode( $json, true, 8, JSON_THROW_ON_ERROR );
		} catch ( \JsonException ) {
			return false; }
		return is_array( $s ) && ( $s['type'] ?? null ) === ( $registration ? 'webauthn.create' : 'webauthn.get' ) && $context->acceptOrigin( $s['origin'] ?? null ) && is_string( $s['challenge'] ?? null ) && strlen( $s['challenge'] ) <= 128 && hash_equals( $challenge, $s['challenge'] ) && ( ! array_key_exists( 'crossOrigin', $s ) || false === $s['crossOrigin'] ) && ! array_key_exists( 'topOrigin', $s );
	}
	private function keys( array $value, array $expected ): bool {
		$actual = array_keys( $value );
		sort( $actual );
		sort( $expected );
		return $actual === $expected; }
}
