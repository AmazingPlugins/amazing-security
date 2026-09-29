<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

final class LoginView {
	public function __construct(
		public readonly string $formAction,
		public readonly array $nonces,
		public readonly string $rateMode,
		public readonly bool $xmlRpcDisabled,
		public readonly bool $enrolled,
		public readonly bool $https,
		public readonly string $username,
		public readonly bool $eraseOnUninstall = false
	) {}
}
