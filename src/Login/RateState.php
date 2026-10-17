<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Login;

defined( 'ABSPATH' ) || exit;

final class RateState {
	public function __construct(
		public readonly int $failures,
		public readonly int $windowStartedAt,
		public readonly int $blockedUntil,
		public readonly bool $available = true
	) {}

	public static function empty( int $now ): self {
		return new self( 0, $now, 0 );
	}

	public static function unavailable(): self {
		return new self( 0, 0, 0, false );
	}

	public function isBlocked( int $now ): bool {
		return $this->available && $this->blockedUntil > $now;
	}

	public function afterFailure( int $now ): self {
		if ( ! $this->available ) {
			return $this;
		}
		if ( $now >= $this->windowStartedAt + 900 ) {
			return new self( 1, $now, 0 );
		}
		if ( $this->isBlocked( $now ) ) {
			return $this;
		}
		$failures = min( 5, $this->failures + 1 );
		return new self( $failures, $this->windowStartedAt, 5 === $failures ? $now + 900 : 0 );
	}
}
