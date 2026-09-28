<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Checks;

use AmazingPlugins\Security\Scan\ScanContext;

final class HttpsAdminCheck extends AbstractCheck {
	public function id(): string {
		return 'https-admin'; }
	public function run( ScanContext $context ): array {
		$https = $this->values->adminUsesHttps();
		return $this->result( null === $https ? null : ! $https, 'The administrator URL uses HTTPS.', 'The administrator URL does not use HTTPS. Configure HTTPS for the site.' ); }
}
