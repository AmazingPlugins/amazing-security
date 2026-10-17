<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Login;

defined( 'ABSPATH' ) || exit;

interface RateCounterStore {
	public function state( string $addressKey, int $now ): RateState;
	public function recordFailure( string $addressKey, int $now ): RateState;
	public function clearExpired( int $now ): void;
}
