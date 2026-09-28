<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Integrity;

final class HttpResult {
	public function __construct( public readonly int $status, public readonly string $body ) {}
}
