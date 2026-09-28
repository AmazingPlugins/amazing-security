<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Integrity;

final class WordPressOptions implements OptionGateway {
	public function get( string $key ): mixed {
		return get_option( $key, null );
	}

	public function add( string $key, string $value ): bool {
		return add_option( $key, $value, '', false );
	}

	public function set( string $key, string $value ): bool {
		return update_option( $key, $value, false );
	}

	public function delete( string $key ): void {
		delete_option( $key );
	}
}
