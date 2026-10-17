<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Integrity;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Scan\ScanRun;

interface IntegrityStore {
	public function begin( string $scanId, IntegrityCursor $cursor ): bool;
	public function saveProgress( string $scanId, IntegrityStep $step ): void;
	public function complete( string $scanId, ScanRun $run ): void;
	public function latestProgress(): ?IntegrityStep;
	public function latestCompleted(): ?ScanRun;
}
