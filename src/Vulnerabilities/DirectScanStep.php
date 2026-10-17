<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Vulnerabilities;

defined( 'ABSPATH' ) || exit;

final class DirectScanStep {
	public function __construct( public readonly int $nextOffset, public readonly ?VulnerabilityReport $report, public readonly bool $allFetched = false, public readonly string $phase = 'feed', public readonly array $verified = array() ) {}
}
