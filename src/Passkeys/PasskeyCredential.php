<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Passkeys;

defined( 'ABSPATH' ) || exit;

final class PasskeyCredential {
	public function read( mixed $raw, int $now ): ?array {
		$s = PasskeyState::object( $raw, 8192, array( 'version', 'user_id', 'credential_id', 'user_handle', 'public_key', 'origin', 'rp_id', 'context_revision', 'counter', 'backup_eligible', 'backed_up', 'label', 'created_at', 'last_used_at', 'revision' ) );
		if ( null === $s || 1 !== $s['version'] || ! PasskeyState::integer( $s['user_id'], 1, PHP_INT_MAX ) || ! is_string( $s['credential_id'] ) || '' === ( Base64Url::decode( $s['credential_id'], 1024 ) ?? '' ) || ! is_string( $s['user_handle'] ) || 32 !== strlen( Base64Url::decode( $s['user_handle'], 32 ) ?? '' ) || ! is_string( $s['public_key'] ) || ! ( new PasskeyVerifier() )->supportedKey( $s['public_key'] ) || ! is_string( $s['origin'] ) || ! is_string( $s['rp_id'] ) || ! PasskeyState::integer( $s['counter'], 0, 4294967295 ) || ! is_bool( $s['backup_eligible'] ) || ! is_bool( $s['backed_up'] ) || ( $s['backed_up'] && ! $s['backup_eligible'] ) || ! is_string( $s['label'] ) || '' === $s['label'] || strlen( $s['label'] ) > 80 || 1 !== preg_match( '//u', $s['label'] ) || 1 === preg_match( '/[\x00-\x1f\x7f]/', $s['label'] ) || ! PasskeyState::integer( $s['created_at'], 1, $now ) || ! is_int( $s['last_used_at'] ) || ( 0 !== $s['last_used_at'] && ! PasskeyState::integer( $s['last_used_at'], $s['created_at'], $now ) ) || ! PasskeyState::hex( $s['revision'], 32 ) ) {
			return null; }
		$context = PasskeyContext::fromSiteUrl( $s['origin'] );
		return null !== $context && $context->bindingUrl() === $s['origin'] && $context->rpId() === $s['rp_id'] && $context->fingerprint() === $s['context_revision'] ? $s : null;
	}
}
