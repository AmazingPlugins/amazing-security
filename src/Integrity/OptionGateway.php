<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Integrity;

defined( 'ABSPATH' ) || exit;

interface OptionGateway {
	public function get( string $key ): mixed;
	public function add( string $key, string $value ): bool;
	public function set( string $key, string $value ): bool;
	public function delete( string $key ): void;
	public function replaceIfSame( string $key, string $expected, string $replacement ): bool;
	public function deleteIfSame( string $key, string $expected ): bool;
}
