<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Alerts;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\FileScan\FileScanReport;
use AmazingPlugins\Security\Scan\ScanRun;
use AmazingPlugins\Security\Vulnerabilities\VulnerabilityReport;

final class AlertNotifier {
	public function __construct( private readonly AlertPolicy $policy, private readonly AlertDelivery $delivery ) {}

	public function integrity( ScanRun $run, int $now ): string {
		// A partial run still mails what it confirmed; earlier findings it didn't reach stay active.
		return $this->delivery->sendNew( $this->policy->fromIntegrity( $run ), $now, 'integrity', ! $run->partial );
	}

	public function files( FileScanReport $report, int $now ): string {
		return $this->delivery->sendNew( $this->policy->fromFiles( $report ), $now, 'files', ! $report->partial );
	}

	public function vulnerabilities( VulnerabilityReport $report, int $now ): string {
		return $this->delivery->sendNew( $this->policy->fromVulnerabilities( $report ), $now, 'vulnerabilities', ! $report->partial );
	}
}
