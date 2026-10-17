<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Proxy;

defined( 'ABSPATH' ) || exit;

final class ProxyNamespace {
	public static function salt( string $salt, ?array $policy ): string {
		return null !== $policy && str_repeat( '0', 32 ) !== $policy['revision'] ? $salt . ':proxy:' . $policy['revision'] : $salt; }
}
