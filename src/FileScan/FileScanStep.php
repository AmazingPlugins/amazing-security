<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\FileScan;

defined( 'ABSPATH' ) || exit;

final class FileScanStep {
	public function __construct( public readonly FileScanCursor $cursor, public readonly bool $finished, public readonly array $observations = array() ) {}

	public function extraExecutablePaths(): array {
		return array_values( array_map( static fn( array $item ): string => $item['path'], array_filter( $this->observations, static fn( array $item ): bool => $item['extra'] && (bool) preg_match( '/\.(?:php|phtml|php[0-9]+)$/iD', $item['path'] ) ) ) );
	}
}
