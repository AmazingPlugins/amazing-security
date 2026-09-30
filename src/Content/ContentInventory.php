<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Content;

interface ContentInventory {
	public function bounds(): array;
	public function candidates( string $kind, int $after, int $max, int $limit ): array;
	public function read( string $kind, int $id, string $hash ): ?string;
}
