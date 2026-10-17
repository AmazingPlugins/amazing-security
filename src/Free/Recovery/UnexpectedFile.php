<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Free\Recovery;

defined( 'ABSPATH' ) || exit;

/** Moves one unexpected file out of uploads, a theme, or a plugin. */
final class UnexpectedFile {
	private readonly string $root;
	private readonly string $pluginMainFile;
	private readonly string $backupDirectory;

	public function __construct( string $root, string $pluginMainFile, string $backupDirectory ) {
		$this->root            = self::trim( $root );
		$this->pluginMainFile  = self::trim( $pluginMainFile );
		$this->backupDirectory = self::trim( $backupDirectory );
	}

	public function remove( string $relativePath, string $phrase, Approval $approval ): ChangeResult {
		$denial = $approval->denial();
		if ( null !== $denial ) {
			return ChangeResult::failure( $denial );
		}
		if ( strlen( $relativePath ) > 1024 || 1 !== preg_match( '#\A[a-z0-9_./-]+\z#', $relativePath ) || str_contains( $relativePath, '..' ) || str_starts_with( $relativePath, '/' ) ) {
			return ChangeResult::failure( __( 'That path is not allowed. No file was removed.', 'amazing-security' ) );
		}
		$allowed = false;
		foreach ( array( 'wp-content/uploads/', 'wp-content/themes/', 'wp-content/plugins/' ) as $prefix ) {
			if ( str_starts_with( $relativePath, $prefix ) && strlen( $relativePath ) > strlen( $prefix ) ) {
				$allowed = true;
				break;
			}
		}
		if ( ! $allowed ) {
			return ChangeResult::failure( __( 'That path is not under uploads, a theme, or a plugin. No file was removed.', 'amazing-security' ) );
		}
		if ( 'DELETE' !== $phrase ) {
			return ChangeResult::failure( __( 'Type DELETE to remove the file. No file was removed.', 'amazing-security' ) );
		}
		$target = ( new InstallPath( $this->root ) )->regularFile( $relativePath );
		if ( null === $target || ! $this->inTree( $target ) ) {
			return ChangeResult::failure( __( 'That file is not a real file inside the install. No file was removed.', 'amazing-security' ) );
		}
		$base = basename( $target );
		if ( 'wp-config.php' === $base || '.htaccess' === $base ) {
			return ChangeResult::failure( __( 'wp-config.php and .htaccess are left in place.', 'amazing-security' ) );
		}
		if ( $this->isPluginMain( $target ) ) {
			return ChangeResult::failure( __( 'The plugin main file cannot be removed.', 'amazing-security' ) );
		}
		$moved = ( new PrivateBackup( $this->root, $this->backupDirectory ) )->move( $target );
		if ( ! $moved['removed'] ) {
			return ChangeResult::failure( __( 'The private backup could not be written. The file was left in place.', 'amazing-security' ) );
		}
		clearstatcache( true, $target );
		if ( is_file( $target ) || is_link( $target ) ) {
			return ChangeResult::failure( __( 'The file is still in place.', 'amazing-security' ) );
		}
		return ChangeResult::success( __( 'The file was moved out of the site into a private temp backup.', 'amazing-security' ) );
	}

	private function inTree( string $target ): bool {
		$root = realpath( $this->root );
		if ( false === $root || ! InstallPath::inside( $target, $root ) || $target === $root ) {
			return false;
		}
		foreach ( array( 'wp-content/uploads', 'wp-content/themes', 'wp-content/plugins' ) as $relative ) {
			$directory = $this->root . '/' . $relative;
			if ( is_link( $directory ) ) {
				continue;
			}
			$base = realpath( $directory );
			if ( false !== $base && InstallPath::inside( $target, $base ) && $target !== $base ) {
				return true;
			}
		}
		return false;
	}

	private function isPluginMain( string $target ): bool {
		if ( '' === $this->pluginMainFile || is_link( $this->pluginMainFile ) || ! str_ends_with( strtolower( $target ), '.php' ) ) {
			return false;
		}
		$main = realpath( $this->pluginMainFile );
		return false !== $main && $main === $target;
	}

	private static function trim( string $path ): string {
		$trimmed = rtrim( $path, '/\\' );
		return '' === $trimmed ? $path : $trimmed;
	}
}
