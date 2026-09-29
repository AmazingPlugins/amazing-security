<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Vulnerabilities;

final class SnapshotResult {
	public function __construct( public readonly string $state, public readonly string $reason, public readonly ?Snapshot $snapshot = null ) {}
}
