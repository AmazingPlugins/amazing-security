<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Integrity;

defined( 'ABSPATH' ) || exit;

final class IntegrityStep {
	public function __construct( public readonly IntegrityCursor $cursor, public readonly bool $finished ) {}
}
