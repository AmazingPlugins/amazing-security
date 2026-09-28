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

	public function replaceIfSame( string $key, string $expected, string $replacement ): bool {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Atomic compare-and-swap prevents one scan overwriting another.
		$changed = $wpdb->query( $wpdb->prepare( "UPDATE {$wpdb->options} SET option_value = %s WHERE option_name = %s AND BINARY option_value = BINARY %s", $replacement, $key, $expected ) );
		if ( 1 !== $changed ) {
			return false;
		}
		wp_cache_delete( $key, 'options' );
		return true;
	}

	public function deleteIfSame( string $key, string $expected ): bool {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Only remove the exact scan value that this request observed.
		$changed = $wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name = %s AND BINARY option_value = BINARY %s", $key, $expected ) );
		if ( 1 !== $changed ) {
			return false;
		}
		wp_cache_delete( $key, 'options' );
		return true;
	}
}
