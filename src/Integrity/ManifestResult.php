<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Integrity;

final class ManifestResult {
	public function __construct( public readonly ?Manifest $manifest, public readonly string $reason = '' ) {}
}
