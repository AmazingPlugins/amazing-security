<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Integrity;

interface OptionGateway {
	public function get( string $key ): mixed;
	public function add( string $key, string $value ): bool;
	public function set( string $key, string $value ): bool;
	public function delete( string $key ): void;
}
