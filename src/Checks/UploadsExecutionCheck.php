<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Checks;

use AmazingPlugins\Security\Findings\CheckResult;
use AmazingPlugins\Security\Findings\State;
use AmazingPlugins\Security\Scan\ScanContext;
use AmazingPlugins\Security\Scan\SecurityCheck;
use DateTimeImmutable;

final class UploadsExecutionCheck implements SecurityCheck {
	public function id(): string {
		return 'uploads-php-execution';
	}

	public function run( ScanContext $context ): array {
		return array( new CheckResult( $this->id(), State::UNKNOWN, 'PHP execution in uploads has not been verified. Ask your host to confirm its effective Apache/Nginx execution policy. Local permissions and .htaccess contents cannot prove runtime behavior. No executable probe was written.', 'https://developer.wordpress.org/advanced-administration/security/hardening/', new DateTimeImmutable(), 'low', 'unavailable', array( 'method' => 'no_runtime_probe' ) ) );
	}
}
