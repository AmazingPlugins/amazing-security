<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Passkeys;

/** Reuses native account/factor policy through fresh state callbacks; never grants cookies itself. */
final class PasskeyAccountGate {
	public function __construct( private readonly \Closure $readState, private readonly \Closure $verifyFactor, private readonly \Closure $grantGrace, private readonly \Closure $filterAccount ) {}
	public function authorize( int $userId, string $factor, int $now, bool $consumeFactor = true ): ?array {
		if ( $userId < 1 || $now < 0 || strlen( $factor ) > 128 ) {
			return null; }
		try {
			$state = ( $this->readState )( $userId, $now );
			if ( ! $this->allowed( $state, $userId, true ) ) {
				return null; }
			if ( 'new' === $state['required'] ) {
				if ( ! ( $this->grantGrace )( $userId, $state['policy_revision'], $now ) ) {
					return null; }
				$fresh = ( $this->readState )( $userId, $now );
				if ( ! $this->allowed( $fresh, $userId, false ) || 'grace' !== $fresh['required'] || $fresh['policy_revision'] !== $state['policy_revision'] || $fresh['account_revision'] !== $state['account_revision'] ) {
					return null; }
				$state = $fresh;
			}
			$user = ( $this->filterAccount )( $state['user'] );
			if ( ! $user instanceof \WP_User || $user->ID !== $userId ) {
				return null; }
			if ( $consumeFactor && $state['admin'] && $state['enrolled'] && ! ( $this->verifyFactor )( $userId, $factor, $now ) ) {
				return null; }
			$permit = array(
				'user_id'     => $userId,
				'user'        => $user,
				'fingerprint' => $state['fingerprint'],
			);
			return null !== $this->finalCheck( $permit, $now ) ? $permit : null;
		} catch ( \Throwable $error ) {
			return null; }
	}
	public function finalCheck( array $permit, int $now ): ?\WP_User {
		if ( ! is_int( $permit['user_id'] ?? null ) || ! ( $permit['user'] ?? null ) instanceof \WP_User || $permit['user']->ID !== $permit['user_id'] || ! PasskeyState::hex( $permit['fingerprint'] ?? null, 64 ) || $now < 0 ) {
			return null; }
		try {
			$state = ( $this->readState )( $permit['user_id'], $now );
			return $this->allowed( $state, $permit['user_id'], false ) && hash_equals( $permit['fingerprint'], $state['fingerprint'] ) ? $permit['user'] : null;
		} catch ( \Throwable $error ) {
			return null; }
	}
	private function allowed( mixed $state, int $userId, bool $allowNew ): bool {
		if ( ! is_array( $state ) || ! ( $state['user'] ?? null ) instanceof \WP_User || $state['user']->ID !== $userId || ! is_bool( $state['admin'] ?? null ) || ! is_bool( $state['enrolled'] ?? null ) || false !== ( $state['reset_required'] ?? null ) || ! is_string( $state['policy_revision'] ?? null ) || ( '' !== $state['policy_revision'] && ! PasskeyState::hex( $state['policy_revision'], 32 ) ) || ! PasskeyState::hex( $state['account_revision'] ?? null, 64 ) || ! PasskeyState::hex( $state['fingerprint'] ?? null, 64 ) ) {
			return false; }
		if ( ! $state['admin'] ) {
			return ! $state['enrolled'] && 'off' === ( $state['required'] ?? null ); }
		if ( $state['enrolled'] ) {
			return in_array( $state['required'] ?? null, array( 'off', 'enrolled' ), true ); }
		return in_array( $state['required'] ?? null, $allowNew ? array( 'off', 'grace', 'new' ) : array( 'off', 'grace' ), true );
	}
}
