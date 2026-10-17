<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Checks;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Scan\ScanContext;

final class HttpsAdminCheck extends AbstractCheck {
	public function id(): string {
		return 'https-admin'; }
	public function run( ScanContext $context ): array {
		$https = $this->values->adminUsesHttps();
		return $this->result( null === $https ? null : ! $https, 'The admin address uses HTTPS.', 'The admin address is not using HTTPS. Turn on HTTPS for this site before you change other security settings.' ); }
}
