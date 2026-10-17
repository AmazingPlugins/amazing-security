<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Sessions;

defined( 'ABSPATH' ) || exit;

/** Names saved application passwords. It does not reveal or send the password. */
final class ApplicationPasswordList {
	public static function rows( array $stored ): array {
		$rows = array();
		foreach ( array_slice( $stored, 0, 50 ) as $item ) {
			if ( ! is_array( $item ) ) {
				continue;
			}
			$uuid = $item['uuid'] ?? '';
			$name = $item['name'] ?? '';
			if ( ! is_string( $uuid ) ) {
				continue;
			}
			$uuid = strtolower( $uuid );
			if ( 1 !== preg_match( '/^[a-f0-9-]{36}$/D', $uuid ) ) {
				continue;
			}
			if ( ! is_string( $name ) || '' === $name || strlen( $name ) > 100 ) {
				$name = __( 'Unnamed', 'amazing-security' );
			}
			$rows[] = array(
				'uuid'    => $uuid,
				'name'    => $name,
				'created' => max( 0, (int) ( $item['created'] ?? 0 ) ),
			);
		}
		return $rows;
	}

	public static function selected( array $rows, string $uuid ): string {
		if ( 1 !== preg_match( '/^[a-f0-9-]{36}$/D', $uuid ) ) {
			return '';
		}
		$match = '';
		foreach ( $rows as $row ) {
			if ( ! is_array( $row ) || ! is_string( $row['uuid'] ?? null ) || ! hash_equals( $row['uuid'], $uuid ) ) {
				continue;
			}
			if ( '' !== $match ) {
				return '';
			}
			$match = $row['uuid'];
		}
		return $match;
	}
}
