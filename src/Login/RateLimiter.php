<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Login;

defined( 'ABSPATH' ) || exit;

final class RateLimiter {
	public function __construct( private LoginSettings $settings, private RateCounterStore $store ) {}

	public function beforePassword( ?string $addressKey, int $now ): RateDecision {
		$mode = $this->settings->rateMode();
		if ( 'off' === $mode ) {
			return new RateDecision( false, 'off' );
		}
		if ( null === $addressKey ) {
			return new RateDecision( false, 'unknown' );
		}
		$state = $this->store->state( $addressKey, $now );
		if ( ! $state->available ) {
			return new RateDecision( false, 'unknown' );
		}
		$blocked = 'block' === $mode && $state->isBlocked( $now );
		return new RateDecision( $blocked, 'observed', $blocked ? min( 900, $state->blockedUntil - $now ) : 0 );
	}

	public function afterFailure( ?string $addressKey, int $now ): void {
		if ( 'off' !== $this->settings->rateMode() && null !== $addressKey ) {
			$this->store->recordFailure( $addressKey, $now );
		}
	}
}
