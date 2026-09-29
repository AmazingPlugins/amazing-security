<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Login;

final class RateDecision {
	public function __construct(
		public readonly bool $blocked,
		public readonly string $coverage,
		public readonly int $retryAfter = 0
	) {}
}
