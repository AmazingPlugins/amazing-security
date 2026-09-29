<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Vulnerabilities;

final class InstalledSoftware {
	public function __construct(
		public readonly string $type,
		public readonly string $slug,
		public readonly string $version,
		public readonly bool $eligible
	) {}

	public function toArray(): array {
		return array(
			'type'     => $this->type,
			'slug'     => $this->slug,
			'version'  => $this->version,
			'eligible' => $this->eligible,
		);
	}
}
