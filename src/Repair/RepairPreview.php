<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Repair;

defined( 'ABSPATH' ) || exit;

final class RepairPreview {
	public function __construct( public readonly RepairCandidate $candidate, public readonly RepairBytes $replacement, public readonly string $root ) {}
}
