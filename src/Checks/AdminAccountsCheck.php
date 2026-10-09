<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Checks;

use AmazingPlugins\Security\Scan\ScanContext;

final class AdminAccountsCheck extends AbstractCheck {
	public function id(): string {
		return 'default-admin-login'; }
	public function run( ScanContext $context ): array {
		return $this->result( $this->values->hasDefaultAdminLogin(), 'No checked administrator uses admin as a login or as the name shown on the site.', 'An administrator uses admin as a login or as the name shown on the site. Open Users and change it.' ); }
}
