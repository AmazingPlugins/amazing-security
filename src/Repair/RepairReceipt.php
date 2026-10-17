<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Repair;

defined( 'ABSPATH' ) || exit;

final class RepairReceipt {
	public function __construct( public readonly string $relativePath, public readonly string $backupPath, public readonly string $beforeSha256, public readonly string $afterSha256 ) {}

	public function toArray(): array {
		return array(
			'relative_path' => $this->relativePath,
			'backup_path'   => $this->backupPath,
			'before_sha256' => $this->beforeSha256,
			'after_sha256'  => $this->afterSha256,
		);
	}

	public static function fromArray( array $data ): ?self {
		foreach ( array( 'relative_path', 'backup_path', 'before_sha256', 'after_sha256' ) as $key ) {
			if ( ! is_string( $data[ $key ] ?? null ) ) {
				return null;
			}
		}
		return new self( $data['relative_path'], $data['backup_path'], $data['before_sha256'], $data['after_sha256'] );
	}
}
