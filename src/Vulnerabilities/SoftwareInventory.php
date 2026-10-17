<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Vulnerabilities;

defined( 'ABSPATH' ) || exit;

interface SoftwareInventory {
	/** @return InstalledSoftware[] */
	public function collect(): array;

	public function complete(): bool;
}
