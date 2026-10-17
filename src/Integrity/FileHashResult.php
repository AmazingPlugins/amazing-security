<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Integrity;

defined( 'ABSPATH' ) || exit;

final class FileHashResult {
	public function __construct( public readonly string $state, public readonly ?string $digest = null, public readonly ?string $sha256 = null ) {}
}
