<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Integrity;

interface ChecksumManifestProvider {
	public function core( string $version, string $locale ): ManifestResult;
	public function plugin( string $slug, string $version ): ManifestResult;
}
