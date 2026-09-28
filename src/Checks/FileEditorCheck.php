<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Checks;

use AmazingPlugins\Security\Scan\ScanContext;

final class FileEditorCheck extends AbstractCheck {
	public function id(): string {
		return 'file-editor'; }
	public function run( ScanContext $context ): array {
		$disabled = $this->values->fileEditorDisabled();
		return $this->result( null === $disabled ? null : ! $disabled, 'The built-in theme and plugin file editor is disabled.', 'The built-in file editor is available. Consider setting DISALLOW_FILE_EDIT.' ); }
}
