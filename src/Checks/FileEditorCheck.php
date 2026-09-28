<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Checks;

use AmazingPlugins\Security\Scan\ScanContext;

final class FileEditorCheck extends AbstractCheck {
	public function id(): string {
		return 'file-editor';
	}

	public function run( ScanContext $context ): array {
		$disabled = $this->values->fileEditorDisabled();
		return $this->result( null === $disabled ? null : ! $disabled, 'DISALLOW_FILE_EDIT is enabled.', 'DISALLOW_FILE_EDIT is not enabled. Other controls may still restrict the editor.' );
	}
}
