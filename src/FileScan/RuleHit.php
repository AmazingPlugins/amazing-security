<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\FileScan;

defined( 'ABSPATH' ) || exit;

final class RuleHit {
	public function __construct( public readonly string $ruleId, public readonly string $version, public readonly string $relativePath, public readonly int $line, public readonly string $summary ) {}
}
