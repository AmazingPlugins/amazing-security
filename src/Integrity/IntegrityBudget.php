<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Integrity;

final class IntegrityBudget {
	private int $files = 0;
	private int $bytes = 0;
	private float $started;

	public function __construct( private readonly int $maxFiles = 250, private readonly int $maxBytes = 33554432, private readonly float $maxSeconds = 5.0, private readonly float $externalSeconds = 5.0 ) {
		$this->started = microtime( true );
	}

	public function beginFile(): bool {
		if ( $this->files >= $this->maxFiles || ! $this->hasTime() ) {
			return false;
		}
		++$this->files;
		return true;
	}

	public function addBytes( int $bytes ): bool {
		if ( $bytes < 0 || $this->bytes + $bytes > $this->maxBytes || ! $this->hasTime() ) {
			return false;
		}
		$this->bytes += $bytes;
		return true;
	}

	public function hasTime(): bool {
		return microtime( true ) - $this->started < min( $this->maxSeconds, $this->externalSeconds );
	}

	public function bytes(): int {
		return $this->bytes;
	}

	public function remainingBytes(): int {
		return max( 0, $this->maxBytes - $this->bytes );
	}
}
