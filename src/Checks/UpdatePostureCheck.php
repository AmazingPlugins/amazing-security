<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Checks;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Scan\ScanContext;

final class UpdatePostureCheck extends AbstractCheck {
	public function id(): string {
		return 'core-updates'; }
	public function run( ScanContext $context ): array {
		return $this->result( $this->values->coreUpdateAvailable(), __( 'WordPress does not report a core update waiting.', 'amazing-security-scanner' ), __( 'A WordPress update is waiting. Open Dashboard, then Updates, and review it.', 'amazing-security-scanner' ) ); }
}
