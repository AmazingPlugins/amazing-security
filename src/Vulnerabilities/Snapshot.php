<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Vulnerabilities;

defined( 'ABSPATH' ) || exit;

final class Snapshot {
	public function __construct(
		public readonly int $sequence,
		public readonly string $generatedAt,
		public readonly string $expiresAt,
		public readonly string $inventoryHash,
		public readonly array $records
	) {}

	public function toArray(): array {
		return array(
			'sequence'       => $this->sequence,
			'generated_at'   => $this->generatedAt,
			'expires_at'     => $this->expiresAt,
			'inventory_hash' => $this->inventoryHash,
			'records'        => $this->records,
		);
	}

	public static function fromArray( array $data ): ?self {
		if ( ! is_int( $data['sequence'] ?? null ) || ! is_string( $data['generated_at'] ?? null ) || ! is_string( $data['expires_at'] ?? null ) || ! is_string( $data['inventory_hash'] ?? null ) || ! is_array( $data['records'] ?? null ) ) {
			return null;
		}
		return new self( $data['sequence'], $data['generated_at'], $data['expires_at'], $data['inventory_hash'], $data['records'] );
	}
}
