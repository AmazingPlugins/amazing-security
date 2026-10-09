<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Free\Recovery;

/** Replaces one existing core or active-theme file from caller-supplied bytes. */
final class CoreFileRepair {
	private readonly string $root;
	private readonly string $themeDirectory;
	private readonly string $backupDirectory;

	public function __construct( string $root, string $themeDirectory, string $backupDirectory ) {
		$this->root            = self::trim( $root );
		$this->themeDirectory  = self::trim( $themeDirectory );
		$this->backupDirectory = self::trim( $backupDirectory );
	}

	public function replace( string $relativePath, string $expectedSha256, string $bytes, Approval $approval, bool $confirmed ): ChangeResult {
		$denial = $approval->denial();
		if ( null !== $denial ) {
			return ChangeResult::failure( $denial );
		}
		if ( ! $confirmed ) {
			return ChangeResult::failure( __( 'Confirm the file repair before writing.', 'amazing-security' ) );
		}
		if ( strlen( $bytes ) > DatabaseDump::MAX_BYTES ) {
			return ChangeResult::failure( __( 'The replacement is larger than 20 MB. The file was not written.', 'amazing-security' ) );
		}
		if ( 1 !== preg_match( '/\A[a-f0-9]{64}\z/', $expectedSha256 ) || ! hash_equals( $expectedSha256, hash( 'sha256', $bytes ) ) ) {
			return ChangeResult::failure( __( 'The replacement hash does not match the supplied bytes. The file was not written.', 'amazing-security' ) );
		}
		$target = $this->resolve( $relativePath );
		if ( null === $target ) {
			return ChangeResult::failure( __( 'That file is not a real core or active theme file inside the install. Nothing was written.', 'amazing-security' ) );
		}
		$backup = new PrivateBackup( $this->root, $this->backupDirectory );
		if ( null === $backup->directory() ) {
			return ChangeResult::failure( __( 'A private temp directory outside the site is not writable. The file was not written.', 'amazing-security' ) );
		}
		$size = filesize( $target );
		if ( false === $size || $size > DatabaseDump::MAX_BYTES ) {
			return ChangeResult::failure( __( 'The current file is larger than 20 MB. The file was not written.', 'amazing-security' ) );
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Read the existing file before replacing it.
		$old = file_get_contents( $target );
		if ( ! is_string( $old ) || strlen( $old ) !== $size ) {
			return ChangeResult::failure( __( 'The current file could not be read. The file was not written.', 'amazing-security' ) );
		}
		if ( null === $backup->write( $old ) ) {
			return ChangeResult::failure( __( 'The private backup could not be written. The file was not written.', 'amazing-security' ) );
		}
		if ( $target !== $this->resolve( $relativePath ) ) {
			return ChangeResult::failure( __( 'The file changed before it could be replaced. The original file was left in place.', 'amazing-security' ) );
		}
		$staged = $this->stage( $target, $bytes );
		if ( null === $staged ) {
			return ChangeResult::failure( __( 'The replacement could not be staged. The original file was left in place.', 'amazing-security' ) );
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.rename_rename -- Atomic same-directory replacement after the hash check.
		if ( ! rename( $staged, $target ) ) {
			if ( is_file( $staged ) && ! is_link( $staged ) ) {
				// phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- Drop the staged file. The original stays.
				unlink( $staged );
			}
			return ChangeResult::failure( __( 'The replacement could not be moved into place. The original file was left in place.', 'amazing-security' ) );
		}
		$digest = hash_file( 'sha256', $target );
		if ( ! is_string( $digest ) || ! hash_equals( $expectedSha256, $digest ) ) {
			$this->restore( $target, $old );
			return ChangeResult::failure( __( 'The written file hash did not match. The previous bytes were put back when that was possible.', 'amazing-security' ) );
		}
		return ChangeResult::success( __( 'The file was replaced. The previous bytes are in a private temp backup.', 'amazing-security' ) );
	}

	private function resolve( string $relative ): ?string {
		$relative = ltrim( $relative, '/' );
		$file     = ( new InstallPath( $this->root ) )->regularFile( $relative );
		if ( null === $file ) {
			return null;
		}
		if ( str_starts_with( $relative, 'wp-includes/' ) ) {
			return $this->under( $file, $this->root . '/wp-includes' ) ? $file : null;
		}
		if ( str_starts_with( $relative, 'wp-admin/' ) ) {
			return $this->under( $file, $this->root . '/wp-admin' ) ? $file : null;
		}
		if ( is_link( $this->themeDirectory ) ) {
			return null;
		}
		$root  = realpath( $this->root );
		$theme = realpath( $this->themeDirectory );
		if ( false === $root || false === $theme || ! InstallPath::inside( $theme, $root ) || $theme === $root ) {
			return null;
		}
		$prefix = ltrim( substr( str_replace( '\\', '/', $theme ), strlen( rtrim( str_replace( '\\', '/', $root ), '/' ) ) ), '/' ) . '/';
		if ( str_starts_with( $relative, $prefix ) && $this->under( $file, $this->themeDirectory ) ) {
			return $file;
		}
		return null;
	}

	private function under( string $file, string $directory ): bool {
		if ( is_link( $directory ) ) {
			return false;
		}
		$base = realpath( $directory );
		return false !== $base && InstallPath::inside( $file, $base ) && $file !== $base;
	}

	private function stage( string $target, string $bytes ): ?string {
		$directory = dirname( $target );
		if ( is_link( $directory ) || ! is_dir( $directory ) ) {
			return null;
		}
		$mode = fileperms( $target );
		$bits = false === $mode ? 0644 : ( $mode & 0777 );
		if ( 0777 === $bits || 0 === $bits ) {
			$bits = 0644;
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_tempnam -- Same-directory temp file for an atomic rename.
		$temp = tempnam( $directory, 'amsec' );
		if ( false === $temp ) {
			return null;
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Stage the checked bytes beside the target.
		$written = file_put_contents( $temp, $bytes );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod -- Keep a normal file mode. 0777 is never applied.
		if ( strlen( $bytes ) !== $written || ! chmod( $temp, $bits ) ) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- Drop a staged file that was not written completely.
			unlink( $temp );
			return null;
		}
		$digest = hash_file( 'sha256', $temp );
		if ( ! is_string( $digest ) || ! hash_equals( hash( 'sha256', $bytes ), $digest ) ) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- Drop a staged file whose hash does not match.
			unlink( $temp );
			return null;
		}
		return $temp;
	}

	private function restore( string $target, string $old ): void {
		$staged = $this->stage( $target, $old );
		if ( null === $staged ) {
			return;
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.rename_rename -- Put the previous bytes back when the new hash does not match.
		if ( ! rename( $staged, $target ) && is_file( $staged ) && ! is_link( $staged ) ) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- Drop a restore stage that could not replace the target.
			unlink( $staged );
		}
	}

	private static function trim( string $path ): string {
		$trimmed = rtrim( $path, '/\\' );
		return '' === $trimmed ? $path : $trimmed;
	}
}
