<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Vulnerabilities;

final class DirectFeedResponse {
	/** @param array<int,array<string,mixed>> $records */
	private function __construct(
		public readonly string $type,
		public readonly string $slug,
		public readonly int $fetchedAt,
		public readonly int $sourceUpdatedAt,
		public readonly array $records
	) {}

	public static function parse( string $type, string $slug, string $json, int $fetchedAt ): ?self {
		if ( ! in_array( $type, array( 'core', 'plugin', 'theme' ), true ) || strlen( $json ) > 512 * 1024 || '' === $json ) {
			return null;
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.json_decode_json_decode -- Bounded untrusted response parsed with explicit checks.
		$data = json_decode( $json, true );
		$key  = $type;
		if ( ! is_array( $data ) || 0 !== ( $data['error'] ?? null ) || ! isset( $data['updated'] ) || ! is_numeric( $data['updated'] ) || ! is_array( $data['data'] ?? null ) ) {
			return null;
		}
		$updated = (int) $data['updated'];
		if ( $updated <= 0 || $updated > $fetchedAt + 300 || ( $data['data'][ $key ] ?? null ) !== $slug ) {
			return null;
		}
		$raw = $data['data']['vulnerability'] ?? null;
		if ( null !== $raw && ( ! is_array( $raw ) || count( $raw ) > 250 || ! array_is_list( $raw ) ) ) {
			return null;
		}
		$records = array();
		foreach ( $raw ?? array() as $row ) {
			if ( ! is_array( $row ) || ! is_string( $row['uuid'] ?? null ) || ! is_string( $row['name'] ?? null ) || strlen( $row['name'] ) > 500 || ! is_array( $row['source'] ?? null ) ) {
				return null;
			}
			if ( 'core' !== $type && ! is_array( $row['operator'] ?? null ) ) {
				return null;
			}
			$records[] = $row;
		}
		return new self( $type, $slug, $fetchedAt, $updated, $records );
	}
}
