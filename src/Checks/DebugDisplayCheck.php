<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Checks;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Findings\CheckResult;
use AmazingPlugins\Security\Findings\State;
use AmazingPlugins\Security\Scan\ScanContext;
use DateTimeImmutable;
use DateTimeZone;

final class DebugDisplayCheck extends AbstractCheck {
	public function id(): string {
		return 'debug-display';
	}

	public function run( ScanContext $context ): array {
		return $this->result( $this->values->debugDisplayed(), __( 'WordPress error details are hidden from visitors.', 'ironlatch-security-scanner' ), __( 'Visitors may see WordPress error details. Set WP_DEBUG_DISPLAY to false in wp-config.php, or turn WP_DEBUG off. This plugin does not edit wp-config.php.', 'ironlatch-security-scanner' ) );
	}
}
