<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Integrity;

defined( 'ABSPATH' ) || exit;

interface ThemeManifestProvider {
	public function theme( string $slug, string $version ): ManifestResult;
}
