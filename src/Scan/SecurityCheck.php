<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Scan;

defined( 'ABSPATH' ) || exit;

interface SecurityCheck {
	public function id(): string;

	/** @return \AmazingPlugins\Security\Findings\CheckResult[] */
	public function run( ScanContext $context ): array;
}
