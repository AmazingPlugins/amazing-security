<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Repair;

final class RepairBytes {
	public function __construct( public readonly string $contents, public readonly string $sha256, public readonly string $sourceUrl ) {}
}
