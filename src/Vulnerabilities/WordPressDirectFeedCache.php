<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Vulnerabilities;

final class WordPressDirectFeedCache implements DirectFeedCache {
	private const INDEX = 'amazing_security_vulnerability_cache_index';

	public function get( string $key ): ?array {
		$value = get_transient( $this->name( $key ) );
		return is_array( $value ) && is_string( $value['body'] ?? null ) && is_int( $value['fetched_at'] ?? null ) ? $value : null;
	}

	public function put( string $key, string $body, int $fetchedAt ): void {
		$name  = $this->name( $key );
		$index = get_option( self::INDEX, array() );
		$index = is_array( $index ) ? $index : array();
		if ( ! in_array( $name, $index, true ) ) {
			// Past the cap nothing new is cached, so "Clear reports" can always find everything that was stored.
			if ( count( $index ) >= 250 ) {
				return;
			}
			$index[] = $name;
			update_option( self::INDEX, $index, false );
		}
		set_transient(
			$name,
			array(
				'body'       => $body,
				'fetched_at' => $fetchedAt,
			),
			DAY_IN_SECONDS
		);
	}

	public function clear(): void {
		$index = get_option( self::INDEX, array() );
		foreach ( is_array( $index ) ? $index : array() as $name ) {
			if ( is_string( $name ) && preg_match( '/^amsec_vuln_[a-f0-9]{32}$/D', $name ) ) {
				delete_transient( $name );
			}
		}
		delete_option( self::INDEX );
		// Anything stored before the index existed or after it was lost.
		global $wpdb;
		$value   = $wpdb->esc_like( '_transient_amsec_vuln_' ) . '%';
		$timeout = $wpdb->esc_like( '_transient_timeout_amsec_vuln_' ) . '%';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Removes only this feature's cached responses.
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s", $value, $timeout ) );
	}

	private function name( string $key ): string {
		return 'amsec_vuln_' . substr( hash( 'sha256', $key ), 0, 32 );
	}
}
