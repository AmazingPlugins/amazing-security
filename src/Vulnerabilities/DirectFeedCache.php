<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Vulnerabilities;

defined( 'ABSPATH' ) || exit;

interface DirectFeedCache {
	/** @return array{body:string,fetched_at:int}|null */
	public function get( string $key ): ?array;

	public function put( string $key, string $body, int $fetchedAt ): void;
}
