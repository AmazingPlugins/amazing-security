<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Headers;

interface HeaderClient {
	public function fetch( string $url ): array;
}
