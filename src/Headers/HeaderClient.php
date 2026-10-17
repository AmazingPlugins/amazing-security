<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Headers;

defined( 'ABSPATH' ) || exit;

interface HeaderClient {
	public function fetch( string $url ): array;
}
