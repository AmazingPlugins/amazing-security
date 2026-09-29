<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\FileScan;

use AmazingPlugins\Security\Integrity\Manifest;

final class FileScanTarget {
	public function __construct( public readonly string $identity, public readonly string $kind, public readonly string $root, public readonly ?Manifest $manifest = null, public readonly ?string $singleFile = null ) {}
}
