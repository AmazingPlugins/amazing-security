<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Checks;

use AmazingPlugins\Security\Scan\ScanContext;

final class AdminAccountsCheck extends AbstractCheck {
	public function id(): string {
		return 'default-admin-login'; }
	public function run( ScanContext $context ): array {
		return $this->result( $this->values->hasDefaultAdminLogin(), 'None of the checked administrators use the login name admin.', 'An administrator uses the login name admin. Add a different administrator, then stop using this login.' ); }
}
