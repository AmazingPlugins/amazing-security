<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Integrity;

final class IntegrityTarget {
	public function __construct( public readonly Manifest $manifest, public readonly string $root ) {}
}
