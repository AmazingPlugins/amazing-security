<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Checks;

use AmazingPlugins\Security\Scan\ScanContext;

final class AdminAccountsCheck extends AbstractCheck {
	public function id(): string {
		return 'default-admin-login'; }
	public function run( ScanContext $context ): array {
		return $this->result( $this->values->hasDefaultAdminLogin(), 'No administrator uses the login name admin in the inspected set.', 'An administrator uses the login name admin. Review privileged accounts.' ); }
}
