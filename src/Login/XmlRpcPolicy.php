<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Login;

defined( 'ABSPATH' ) || exit;

final class XmlRpcPolicy {
	public function __construct( private LoginSettings $settings ) {}

	public function enabled( bool $enabled ): bool {
		return $enabled && ! $this->settings->xmlRpcAuthDisabled();
	}
}
