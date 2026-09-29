<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\FileScan;

final class ContentReadResult {
	public function __construct( public readonly string $state, public readonly string $bytes = '', public readonly string $sha256 = '', public readonly int $size = 0 ) {}

	public function toArray(): array {
		return array(
			'state'  => $this->state,
			'sha256' => $this->sha256,
			'size'   => $this->size,
		);
	}
}
