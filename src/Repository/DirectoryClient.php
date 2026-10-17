<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Repository;

defined( 'ABSPATH' ) || exit;

interface DirectoryClient {
	public function fetch( string $slug, int $now ): array;
}
