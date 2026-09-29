<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\FileScan;

interface FileScanStore {
	public function begin( string $scanId, FileScanCursor $cursor ): bool;
	public function saveProgress( string $scanId, FileScanStep $step ): void;
	public function complete( string $scanId, FileScanReport $report ): void;
	public function latestProgress(): ?FileScanStep;
	public function latestCompleted(): ?FileScanReport;
	/** @return FileScanReport[] */
	public function historicalWarnings(): array;
}
