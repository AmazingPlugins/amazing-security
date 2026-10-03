<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Checks;

interface Values {
	public function coreUpdateAvailable(): ?bool;
	public function debugDisplayed(): ?bool;
	public function debugHiddenByPlugin(): bool;
	public function fileEditorDisabled(): ?bool;

	public function fileEditorFix(): string;
	public function adminUsesHttps(): ?bool;
	public function hasDefaultAdminLogin(): ?bool;
}
