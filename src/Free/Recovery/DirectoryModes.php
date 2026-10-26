<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Free\Recovery;

defined( 'ABSPATH' ) || exit;

/** Read-only mode preview for the main content directories. */
final class DirectoryModes {
	/** @param list<string> $paths */
	public function __construct( private readonly array $paths ) {}

	public static function forSite(): self {
		$uploads = wp_upload_dir( null, false );
		return new self( array_values( array_unique( array( WP_CONTENT_DIR, (string) $uploads['basedir'], WP_PLUGIN_DIR, get_theme_root() ) ) ) );
	}

	/**
	 * @return list<array{path: string, octal: ?string, suggested: string}>
	 */
	public function preview(): array {
		$rows = array();
		foreach ( $this->paths as $path ) {
			$rows[] = array(
				'path'      => $path,
				'octal'     => $this->octal( $path ),
				'suggested' => '0755',
			);
		}
		return $rows;
	}

	private function octal( string $path ): ?string {
		if ( '' === $path || is_link( $path ) || ! is_dir( $path ) ) {
			return null;
		}
		$mode = fileperms( $path );
		return false === $mode ? null : sprintf( '%04o', $mode & 0777 );
	}
}
