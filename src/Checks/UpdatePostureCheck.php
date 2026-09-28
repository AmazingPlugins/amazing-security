<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Checks;

use AmazingPlugins\Security\Scan\ScanContext;

final class UpdatePostureCheck extends AbstractCheck {
	public function id(): string {
		return 'core-updates'; }
	public function run( ScanContext $context ): array {
		return $this->result( $this->values->coreUpdateAvailable(), 'No pending core update was reported by the local update cache.', 'A WordPress core update is available. Review it in Dashboard > Updates.' ); }
}
