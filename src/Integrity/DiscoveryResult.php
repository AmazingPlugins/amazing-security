<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Integrity;

final class DiscoveryResult {
	public function __construct( public readonly array $targets, public readonly array $findings, public readonly string $signature, public readonly bool $partial ) {}
}
