<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Passkeys;

final class PasskeyPending {
	public function read( mixed $raw, int $now ): ?array {
		$s = PasskeyState::object( $raw, 4096, array( 'version', 'purpose', 'user_id', 'session_hash', 'challenge', 'ticket_hash', 'binding_hash', 'policy_revision', 'context_revision', 'created_at', 'expires_at' ) );
		if ( null === $s || 1 !== $s['version'] || ! in_array( $s['purpose'], array( 'login', 'enroll' ), true ) || ! PasskeyState::integer( $s['created_at'], 1, min( $now, PHP_INT_MAX - 300 ) ) || ! is_int( $s['expires_at'] ) || $s['expires_at'] !== $s['created_at'] + 300 || $now >= $s['expires_at'] || ! is_string( $s['challenge'] ) || 32 !== strlen( Base64Url::decode( $s['challenge'], 32 ) ?? '' ) || ! PasskeyState::hex( $s['ticket_hash'], 64 ) || ! PasskeyState::hex( $s['binding_hash'], 64 ) || ! PasskeyState::hex( $s['policy_revision'], 32 ) || ! PasskeyState::hex( $s['context_revision'], 64 ) ) {
			return null; }
		$account = 'login' === $s['purpose'] ? 0 === $s['user_id'] && '' === $s['session_hash'] : PasskeyState::integer( $s['user_id'], 1, PHP_INT_MAX ) && PasskeyState::hex( $s['session_hash'], 64 );
		return $account ? $s : null;
	}
}
