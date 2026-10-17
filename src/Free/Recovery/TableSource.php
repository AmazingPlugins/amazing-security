<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Free\Recovery;

defined( 'ABSPATH' ) || exit;

/** Reads prefixed tables. Tests supply this. Production uses WordPressTables. */
interface TableSource {
	/**
	 * @return list<string>
	 */
	public function tableNames( string $prefix ): array;

	public function createTable( string $table ): ?string;

	/**
	 * @return list<array<string, mixed>>
	 */
	public function rows( string $table, int $limit, int $offset ): array;
}
