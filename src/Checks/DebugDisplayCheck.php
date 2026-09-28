<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Checks;

use AmazingPlugins\Security\Scan\ScanContext;

final class DebugDisplayCheck extends AbstractCheck {
	public function id(): string {
		return 'debug-display'; }
	public function run( ScanContext $context ): array {
		return $this->result( $this->values->debugDisplayed(), 'WordPress debug display is disabled.', 'WordPress debug output may be visible to visitors. Set WP_DEBUG_DISPLAY to false.' ); }
}
