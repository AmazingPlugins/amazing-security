<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Scan;

final class ScanContext {
	public readonly float $deadline;
	public readonly int $entryLimit;

	public function __construct( ?float $deadline = null, int $entryLimit = 5000 ) {
		$this->deadline   = min( $deadline ?? microtime( true ) + 30, microtime( true ) + 30 );
		$this->entryLimit = max( 1, min( 5000, $entryLimit ) );
	}
}
