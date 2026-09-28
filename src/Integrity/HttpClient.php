<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Integrity;

interface HttpClient {
	public function get( string $url, int $maxBytes ): HttpResult;
}
