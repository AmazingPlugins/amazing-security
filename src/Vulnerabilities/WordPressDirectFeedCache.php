<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Vulnerabilities;

defined( 'ABSPATH' ) || exit;

final class WordPressDirectFeedCache implements DirectFeedCache {
	private const INDEX = 'amazing_security_vulnerability_cache_index';

	public function get( string $key ): ?array {
		$value = get_transient( $this->name( $key ) );
		return is_array( $value ) && is_string( $value['body'] ?? null ) && is_int( $value['fetched_at'] ?? null ) ? $value : null;
	}

	public function put( string $key, string $body, int $fetchedAt ): void {
		$name = $this->name( $key );
		set_transient(
			$name,
			array(
				'body'       => $body,
				'fetched_at' => $fetchedAt,
			),
			DAY_IN_SECONDS
		);
		$index = get_option( self::INDEX, array() );
		$index = is_array( $index ) ? $index : array();
		if ( count( $index ) < 250 && ! in_array( $name, $index, true ) ) {
			$index[] = $name;
			update_option( self::INDEX, $index, false );
		}
	}

	public function clear(): void {
		$index = get_option( self::INDEX, array() );
		foreach ( is_array( $index ) ? $index : array() as $name ) {
			if ( is_string( $name ) && preg_match( '/^amsec_vuln_[a-f0-9]{32}$/D', $name ) ) {
				delete_transient( $name );
			}
		}
		delete_option( self::INDEX );
	}

	private function name( string $key ): string {
		return 'amsec_vuln_' . substr( hash( 'sha256', $key ), 0, 32 );
	}
}
