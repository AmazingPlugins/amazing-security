<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Integrity;

defined( 'ABSPATH' ) || exit;

final class WordPressOptions implements OptionGateway {
	public function get( string $key ): mixed {
		return get_option( $key, null );
	}

	public function add( string $key, string $value ): bool {
		global $wpdb;
		// add_option() can overwrite a concurrent insert on older WordPress versions.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Unique-key insert must never replace another worker's state or lease.
		$added = $wpdb->query( $wpdb->prepare( "INSERT IGNORE INTO {$wpdb->options} (option_name, option_value, autoload) VALUES (%s, %s, 'no')", $key, maybe_serialize( $value ) ) );
		wp_cache_delete( $key, 'options' );
		wp_cache_delete( 'notoptions', 'options' );
		if ( 1 === $added ) {
			do_action( 'amsec_option_written', $key );
		}
		return 1 === $added;
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
		// A competing writer can invalidate this request's cached value or cached absence.
		wp_cache_delete( $key, 'options' );
		wp_cache_delete( 'notoptions', 'options' );
		if ( 1 === $changed ) {
			do_action( 'amsec_option_written', $key );
		}
		return 1 === $changed;
	}

	public function deleteIfSame( string $key, string $expected ): bool {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Only remove the exact scan value that this request observed.
		$changed = $wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name = %s AND BINARY option_value = BINARY %s", $key, $expected ) );
		// A competing writer can invalidate this request's cached value or cached absence.
		wp_cache_delete( $key, 'options' );
		wp_cache_delete( 'notoptions', 'options' );
		if ( 1 === $changed ) {
			do_action( 'amsec_option_written', $key );
		}
		return 1 === $changed;
	}
}
