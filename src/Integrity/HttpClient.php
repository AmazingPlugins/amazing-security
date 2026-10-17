<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Integrity;

defined( 'ABSPATH' ) || exit;

interface HttpClient {
	public function get( string $url, int $maxBytes ): HttpResult;
}
