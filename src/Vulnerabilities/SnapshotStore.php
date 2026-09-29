<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Vulnerabilities;

interface SnapshotStore {
	public function latestAccepted(): ?Snapshot;
	public function saveAccepted( SnapshotResult $result ): void;
}
