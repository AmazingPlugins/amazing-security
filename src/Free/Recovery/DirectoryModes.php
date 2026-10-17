<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Free\Recovery;

defined( 'ABSPATH' ) || exit;

/** Preview and 0755 repair for four wp-content directories. */
final class DirectoryModes {
	public const MODE = 0755;

	private readonly string $contentDirectory;

	public function __construct( string $contentDirectory ) {
		$trimmed                = rtrim( $contentDirectory, '/\\' );
		$this->contentDirectory = '' === $trimmed ? $contentDirectory : $trimmed;
	}

	/**
	 * @return list<string>
	 */
	public function allowedPaths(): array {
		$base = $this->contentDirectory;
		return array(
			$base,
			$base . '/uploads',
			$base . '/plugins',
			$base . '/themes',
		);
	}

	/**
	 * @return list<array{path: string, octal: ?string, suggested: string}>
	 */
	public function preview(): array {
		$rows = array();
		foreach ( $this->allowedPaths() as $path ) {
			$rows[] = array(
				'path'      => $path,
				'octal'     => $this->octal( $path ),
				'suggested' => '0755',
			);
		}
		return $rows;
	}

	public function apply( string $path, Approval $approval, bool $confirmed ): ChangeResult {
		$denial = $approval->denial();
		if ( null !== $denial ) {
			return ChangeResult::failure( $denial );
		}
		if ( ! $confirmed ) {
			return ChangeResult::failure( __( 'Confirm the directory before changing its mode.', 'amazing-security' ) );
		}
		if ( 0755 !== self::MODE ) {
			return ChangeResult::failure( __( 'Refusing a directory mode other than 0755.', 'amazing-security' ) );
		}
		if ( ! in_array( $path, $this->allowedPaths(), true ) ) {
			return ChangeResult::failure( __( 'That path is not one of the four directories this page can change.', 'amazing-security' ) );
		}
		if ( is_link( $this->contentDirectory ) || is_link( $path ) || ! is_dir( $path ) ) {
			return ChangeResult::failure( __( 'That path is a link or not a real directory. No mode was changed.', 'amazing-security' ) );
		}
		$root = realpath( $this->contentDirectory );
		$real = realpath( $path );
		if ( false === $root || false === $real || ! InstallPath::inside( $real, $root ) ) {
			return ChangeResult::failure( __( 'That directory resolves outside wp-content. No mode was changed.', 'amazing-security' ) );
		}
		clearstatcache( true, $path );
		if ( is_link( $path ) || ! is_dir( $real ) ) {
			return ChangeResult::failure( __( 'That path is a link or not a real directory. No mode was changed.', 'amazing-security' ) );
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod -- Approved mode change for one allowlisted directory.
		if ( ! chmod( $real, self::MODE ) ) {
			return ChangeResult::failure( __( 'The directory mode could not be changed.', 'amazing-security' ) );
		}
		clearstatcache( true, $real );
		$after = fileperms( $real );
		if ( false === $after || 0777 === ( $after & 0777 ) || self::MODE !== ( $after & 0777 ) ) {
			return ChangeResult::failure( __( 'The directory mode could not be changed.', 'amazing-security' ) );
		}
		return ChangeResult::success( __( 'Directory mode is now 0755.', 'amazing-security' ) );
	}

	private function octal( string $path ): ?string {
		if ( is_link( $this->contentDirectory ) || is_link( $path ) || ! is_dir( $path ) ) {
			return null;
		}
		$root = realpath( $this->contentDirectory );
		$real = realpath( $path );
		if ( false === $root || false === $real || ! InstallPath::inside( $real, $root ) ) {
			return null;
		}
		$mode = fileperms( $path );
		if ( false === $mode ) {
			return null;
		}
		return sprintf( '%04o', $mode & 0777 );
	}
}
