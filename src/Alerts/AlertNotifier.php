<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Alerts;

use AmazingPlugins\Security\FileScan\FileScanReport;
use AmazingPlugins\Security\Scan\ScanRun;

final class AlertNotifier {
	public function __construct( private readonly AlertPolicy $policy, private readonly AlertDelivery $delivery ) {}

	public function integrity( ScanRun $run, int $now ): string {
		return $run->partial ? 'partial' : $this->delivery->sendNew( $this->policy->fromIntegrity( $run ), $now, 'integrity' );
	}

	public function files( FileScanReport $report, int $now ): string {
		return $report->partial ? 'partial' : $this->delivery->sendNew( $this->policy->fromFiles( $report ), $now, 'files' );
	}
}
