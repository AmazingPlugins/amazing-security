<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Checks;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Scan\ScanContext;

final class FileEditorCheck extends AbstractCheck {
	public function id(): string {
		return 'file-editor';
	}

	public function run( ScanContext $context ): array {
		$disabled = $this->values->fileEditorDisabled();
		$fix      = $this->values->fileEditorFix();
		$warn     = 'config' === $fix
			? __( 'People can edit theme and plugin files because wp-config.php turns the editor on. This plugin will not edit that file.', 'amsec-security-scanner' )
			: __( 'People can edit theme and plugin files in wp-admin. Turn that editor off so a signed-in session cannot change PHP from the browser.', 'amsec-security-scanner' );
		return $this->result( null === $disabled ? null : ! $disabled, __( 'The theme and plugin editor is turned off.', 'amsec-security-scanner' ), $warn, array( 'fix' => $fix ) );
	}
}
