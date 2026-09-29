<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Login;

final class EnrollmentResult {
	public function __construct( public readonly bool $allowed, public readonly string $secretBase32 = '' ) {}
}
