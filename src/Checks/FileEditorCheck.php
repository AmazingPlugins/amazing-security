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
		$fix      = $this->values->fileEditorFix();
		$warn     = 'config' === $fix
			? 'People can edit theme and plugin files because wp-config.php turns the editor on. This plugin will not edit that file.'
			: 'People can edit theme and plugin files in wp-admin. Turn that editor off so a signed-in session cannot change PHP from the browser.';
		return $this->result( null === $disabled ? null : ! $disabled, 'The theme and plugin editor is turned off.', $warn, array( 'fix' => $fix ) );
	}
}
