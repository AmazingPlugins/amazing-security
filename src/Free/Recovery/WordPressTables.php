<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Free\Recovery;

/** Prefixed table reads through $wpdb. Queries are prepared, including %i identifiers. */
final class WordPressTables implements TableSource {
	public function __construct( private readonly \wpdb $wpdb ) {}

	public static function escape( string $value ): string {
		if ( ! function_exists( 'esc_sql' ) ) {
			return addslashes( $value );
		}
		$escaped = esc_sql( $value );
		if ( ! is_string( $escaped ) ) {
			return addslashes( $value );
		}
		global $wpdb;
		if ( is_object( $wpdb ) && method_exists( $wpdb, 'remove_placeholder_escape' ) ) {
			$restored = $wpdb->remove_placeholder_escape( $escaped );
			if ( is_string( $restored ) ) {
				return $restored;
			}
		}
		return $escaped;
	}

	public function tableNames( string $prefix ): array {
		$like     = $this->wpdb->esc_like( $prefix ) . '%';
		$prepared = $this->wpdb->prepare( 'SHOW TABLES LIKE %s', $like );
		if ( ! is_string( $prepared ) ) {
			return array();
		}
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- $prepared is the return value of $wpdb->prepare().
		$rows = $this->wpdb->get_results( $prepared, ARRAY_N );
		if ( ! is_array( $rows ) ) {
			return array();
		}
		$names = array();
		foreach ( $rows as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$name = (string) reset( $row );
			if ( str_starts_with( $name, $prefix ) && 1 === preg_match( '/\A[A-Za-z0-9_]+\z/', $name ) ) {
				$names[] = $name;
			}
		}
		return $names;
	}

	public function createTable( string $table ): ?string {
		if ( 1 !== preg_match( '/\A[A-Za-z0-9_]+\z/', $table ) ) {
			return null;
		}
		$prepared = $this->wpdb->prepare( 'SHOW CREATE TABLE %i', $table );
		if ( ! is_string( $prepared ) ) {
			return null;
		}
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- $prepared is the return value of $wpdb->prepare().
		$rows = $this->wpdb->get_results( $prepared, ARRAY_A );
		if ( ! is_array( $rows ) || ! isset( $rows[0] ) || ! is_array( $rows[0] ) ) {
			return null;
		}
		$statement = $rows[0]['Create Table'] ?? null;
		return is_string( $statement ) ? $statement : null;
	}

	public function rows( string $table, int $limit, int $offset ): array {
		if ( 1 !== preg_match( '/\A[A-Za-z0-9_]+\z/', $table ) ) {
			return array();
		}
		$prepared = $this->wpdb->prepare( 'SELECT * FROM %i LIMIT %d OFFSET %d', $table, $limit, $offset );
		if ( ! is_string( $prepared ) ) {
			return array();
		}
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- $prepared is the return value of $wpdb->prepare().
		$rows = $this->wpdb->get_results( $prepared, ARRAY_A );
		if ( ! is_array( $rows ) ) {
			return array();
		}
		$clean = array();
		foreach ( $rows as $row ) {
			if ( is_array( $row ) ) {
				$clean[] = $row;
			}
		}
		return $clean;
	}
}
