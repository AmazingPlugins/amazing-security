<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Vulnerabilities;

interface SoftwareInventory {
	/** @return InstalledSoftware[] */
	public function collect(): array;

	public function complete(): bool;
}
