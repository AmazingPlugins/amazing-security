<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Repair;

use AmazingPlugins\Security\Integrity\WordPressOrgManifestProvider;
use Closure;
use Throwable;

final class AtomicPluginRepair {
	private readonly ?Closure $afterReplace;
	private readonly ?Closure $beforeReplace;

	public function __construct( private readonly string $root, private readonly string $backupRoot, ?callable $afterReplace = null, ?callable $beforeReplace = null ) {
		$this->afterReplace  = null === $afterReplace ? null : Closure::fromCallable( $afterReplace );
		$this->beforeReplace = null === $beforeReplace ? null : Closure::fromCallable( $beforeReplace );
	}

	public function currentSha256( string $relativePath ): ?string {
		$target = $this->safeTarget( $relativePath );
		if ( null === $target || filesize( $target ) > 2097152 ) {
			return null;
		}
		$digest = hash_file( 'sha256', $target );
		return false === $digest ? null : $digest;
	}

	public function apply( string $relativePath, string $beforeSha256, string $approvedSha256, RepairBytes $replacement ): ?RepairReceipt {
		if ( ! $this->hashShape( $beforeSha256 ) || ! $this->hashShape( $approvedSha256 ) || ! hash_equals( $approvedSha256, $replacement->sha256 ) || hash( 'sha256', $replacement->contents ) !== $approvedSha256 || strlen( $replacement->contents ) > 2097152 ) {
			return null;
		}
		$target     = $this->safeTarget( $relativePath );
		$backupRoot = $this->safeBackupRoot();
		if ( null === $target || null === $backupRoot ) {
			return null;
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen,WordPress.PHP.NoSilencedErrors.Discouraged -- Exclusive lock on an existing local file; direct filesystem is required for this recipe.
		$handle = @fopen( $target, 'r+b' );
		if ( false === $handle ) {
			return null;
		}
		$backup = null;
		$temp   = null;
		try {
			if ( ! flock( $handle, LOCK_EX | LOCK_NB ) || $target !== $this->safeTarget( $relativePath ) ) {
				return null;
			}
			$stat = fstat( $handle );
			if ( ! is_array( $stat ) || $stat['size'] > 2097152 || $stat['size'] < 0 ) {
				return null;
			}
			$pathStat = stat( $target );
			if ( false === $pathStat || $pathStat['ino'] !== $stat['ino'] || $pathStat['dev'] !== $stat['dev'] ) {
				return null;
			}
			$contents = stream_get_contents( $handle, 2097153 );
			if ( false === $contents || strlen( $contents ) !== $stat['size'] || ! hash_equals( $beforeSha256, hash( 'sha256', $contents ) ) ) {
				return null;
			}
			$backup = $backupRoot . '/amsec-' . bin2hex( random_bytes( 16 ) ) . '.bak';
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen,WordPress.PHP.NoSilencedErrors.Discouraged -- Exclusive private backup outside the served site.
			$backupHandle = @fopen( $backup, 'xb' );
			if ( false === $backupHandle ) {
				return null;
			}
			// phpcs:ignore WordPress.WP.AlternativeFunctions -- Direct filesystem permissions are required for a private backup.
			$private = chmod( $backup, 0600 );
			$written = 0;
			$length  = strlen( $contents );
			while ( $private && $written < $length ) {
				// phpcs:ignore WordPress.WP.AlternativeFunctions -- Bounded write to an exclusive private backup.
				$part = fwrite( $backupHandle, substr( $contents, $written ) );
				if ( false === $part || 0 === $part ) {
					break;
				}
				$written += $part;
			}
			$flushed = fflush( $backupHandle );
			$durable = function_exists( 'fsync' ) ? fsync( $backupHandle ) : false;
			// phpcs:ignore WordPress.WP.AlternativeFunctions -- Close the private backup stream.
			$closed = fclose( $backupHandle );
			// phpcs:ignore WordPress.PHP.YodaConditions.NotYoda -- Dynamic byte counts and hashes.
			if ( ! $private || ! $flushed || ! $durable || ! $closed || $length !== $written || $beforeSha256 !== hash_file( 'sha256', $backup ) ) {
				return null;
			}
			$temp = $this->stage( dirname( $target ), $replacement->contents, $stat['mode'] & 0777 );
			// phpcs:ignore WordPress.PHP.YodaConditions.NotYoda -- Both sides are dynamic filesystem identities and hashes.
			if ( null === $temp || $target !== $this->safeTarget( $relativePath ) || $beforeSha256 !== hash_file( 'sha256', $target ) ) {
				return null;
			}
			$receipt = new RepairReceipt( $relativePath, $backup, $beforeSha256, $approvedSha256 );
			if ( null !== $this->beforeReplace && true !== ( $this->beforeReplace )( $receipt ) ) {
				return null;
			}
			// Recheck after durable receipt persistence, which may take time.
			// phpcs:ignore WordPress.PHP.YodaConditions.NotYoda -- Dynamic path and hash comparisons.
			if ( $target !== $this->safeTarget( $relativePath ) || $beforeSha256 !== hash_file( 'sha256', $target ) ) {
				return null;
			}
			// phpcs:ignore WordPress.WP.AlternativeFunctions.rename_rename -- Atomic same-directory replacement after hash, inode, and symlink checks.
			if ( ! rename( $temp, $target ) ) {
				return null;
			}
			$temp   = null;
			$backup = null; // The persisted receipt owns the backup once replacement starts.
			try {
				if ( null !== $this->afterReplace ) {
					( $this->afterReplace )( $target );
				}
				// phpcs:ignore WordPress.PHP.YodaConditions.NotYoda -- The approved and observed hashes are dynamic.
				if ( $approvedSha256 !== hash_file( 'sha256', $target ) ) {
					throw new RepairVerificationFailure( $receipt );
				}
			} catch ( Throwable ) {
				throw new RepairVerificationFailure( $receipt );
			}
			return $receipt;
		} finally {
			flock( $handle, LOCK_UN );
			// phpcs:ignore WordPress.WP.AlternativeFunctions -- Close the locked target stream.
			fclose( $handle );
			if ( null !== $temp && file_exists( $temp ) ) {
				// phpcs:ignore WordPress.WP.AlternativeFunctions -- Delete only the staged repair file.
				unlink( $temp );
			}
			if ( null !== $backup && file_exists( $backup ) ) {
				// phpcs:ignore WordPress.WP.AlternativeFunctions -- Delete only the unused private backup.
				unlink( $backup );
			}
		}
	}

	public function rollback( RepairReceipt $receipt ): bool {
		return $this->restore( $receipt, $receipt->afterSha256 );
	}

	public function recover( RepairReceipt $receipt, string $observedSha256 ): bool {
		return $this->hashShape( $observedSha256 ) && $this->restore( $receipt, $observedSha256 );
	}

	public function discardBackup( RepairReceipt $receipt ): bool {
		$root    = $this->safeBackupRoot();
		$backup  = realpath( $receipt->backupPath );
		$current = $this->currentSha256( $receipt->relativePath );
		// phpcs:ignore WordPress.PHP.YodaConditions.NotYoda -- Dynamic backup and current-file hashes.
		if ( null === $root || false === $backup || ! str_starts_with( $backup, $root . '/' ) || ! preg_match( '/^amsec-[a-f0-9]{32}\.bak$/D', basename( $backup ) ) || is_link( $receipt->backupPath ) || null === $current || $receipt->afterSha256 === $current || filesize( $backup ) > 2097152 || $receipt->beforeSha256 !== hash_file( 'sha256', $backup ) ) {
			return false;
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions -- Delete only the obsolete private backup after explicit administrator approval.
		return unlink( $backup );
	}

	private function restore( RepairReceipt $receipt, string $expectedCurrentSha256 ): bool {
		$target         = $this->safeTarget( $receipt->relativePath );
		$backupRoot     = $this->safeBackupRoot();
		$resolvedBackup = realpath( $receipt->backupPath );
		if ( null === $target || null === $backupRoot || false === $resolvedBackup || ! str_starts_with( $resolvedBackup, $backupRoot . '/' ) || ! preg_match( '/^amsec-[a-f0-9]{32}\.bak$/D', basename( $resolvedBackup ) ) || ! $this->hashShape( $receipt->beforeSha256 ) || ! $this->hashShape( $receipt->afterSha256 ) || is_link( $receipt->backupPath ) || ! is_file( $resolvedBackup ) || filesize( $resolvedBackup ) > 2097152 ) {
			return false;
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions -- Read a bounded local private backup, not a remote URL.
		$backup = file_get_contents( $resolvedBackup );
		if ( false === $backup || strlen( $backup ) > 2097152 || ! hash_equals( $receipt->beforeSha256, hash( 'sha256', $backup ) ) ) {
			return false;
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen,WordPress.PHP.NoSilencedErrors.Discouraged -- Lock the current local file before rollback.
		$handle = @fopen( $target, 'r+b' );
		if ( false === $handle ) {
			return false;
		}
		$temp = null;
		try {
			if ( ! flock( $handle, LOCK_EX | LOCK_NB ) || $target !== $this->safeTarget( $receipt->relativePath ) ) {
				return false;
			}
			$stat     = fstat( $handle );
			$pathStat = stat( $target );
			// phpcs:ignore WordPress.PHP.YodaConditions.NotYoda -- Dynamic inode and hash comparisons.
			if ( false === $pathStat || ! is_array( $stat ) || $stat['ino'] !== $pathStat['ino'] || $stat['dev'] !== $pathStat['dev'] || $expectedCurrentSha256 !== hash_file( 'sha256', $target ) ) {
				return false;
			}
			$temp = $this->stage( dirname( $target ), $backup, $stat['mode'] & 0777 );
			// phpcs:ignore WordPress.PHP.YodaConditions.NotYoda -- Dynamic path and hash comparisons.
			if ( null === $temp || $target !== $this->safeTarget( $receipt->relativePath ) || $expectedCurrentSha256 !== hash_file( 'sha256', $target ) ) {
				return false;
			}
			// phpcs:ignore WordPress.WP.AlternativeFunctions.rename_rename -- Atomic rollback to the backed-up bytes.
			if ( ! rename( $temp, $target ) ) {
				return false;
			}
			$temp = null;
			// phpcs:ignore WordPress.PHP.YodaConditions.NotYoda -- The expected and observed hashes are dynamic.
			if ( $receipt->beforeSha256 !== hash_file( 'sha256', $target ) ) {
				return false;
			}
			// phpcs:ignore WordPress.WP.AlternativeFunctions -- Remove the consumed private backup after verified rollback.
			unlink( $resolvedBackup );
			return true;
		} finally {
			flock( $handle, LOCK_UN );
			// phpcs:ignore WordPress.WP.AlternativeFunctions -- Close the locked rollback target.
			fclose( $handle );
			if ( null !== $temp && file_exists( $temp ) ) {
				// phpcs:ignore WordPress.WP.AlternativeFunctions -- Delete only the staged rollback file.
				unlink( $temp );
			}
		}
	}

	private function safeTarget( string $relativePath ): ?string {
		if ( ! WordPressOrgManifestProvider::safePath( $relativePath ) || is_link( $this->root ) ) {
			return null;
		}
		$base = realpath( $this->root );
		if ( false === $base || ! is_dir( $base ) ) {
			return null;
		}
		$path = $base;
		foreach ( explode( '/', $relativePath ) as $part ) {
			$path .= '/' . $part;
			if ( is_link( $path ) ) {
				return null;
			}
		}
		$resolved = realpath( $path );
		// phpcs:ignore WordPress.WP.AlternativeFunctions -- Direct write access is required for atomic local replacement.
		return false !== $resolved && str_starts_with( $resolved, $base . '/' ) && is_file( $resolved ) && is_readable( $resolved ) && is_writable( $resolved ) ? $resolved : null;
	}

	private function safeBackupRoot(): ?string {
		if ( is_link( $this->backupRoot ) ) {
			return null;
		}
		$backup = realpath( $this->backupRoot );
		$site   = realpath( $this->root );
		$mode   = false === $backup ? false : fileperms( $backup );
		// phpcs:ignore WordPress.WP.AlternativeFunctions -- Private backup needs direct local write access.
		return false !== $backup && false !== $site && false !== $mode && 0 === ( $mode & 0077 ) && is_dir( $backup ) && is_writable( $backup ) && ! str_starts_with( $backup . '/', $site . '/' ) ? $backup : null;
	}

	private function stage( string $directory, string $contents, int $mode ): ?string {
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_tempnam -- Same-directory temporary file enables atomic replacement.
		$temp = tempnam( $directory, '.amsec-' );
		if ( false === $temp ) {
			return null;
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Bounded private staged replacement.
		$written = file_put_contents( $temp, $contents );
		// phpcs:ignore WordPress.WP.AlternativeFunctions -- Preserve file mode on atomic staged replacement.
		if ( strlen( $contents ) !== $written || ! chmod( $temp, $mode ) ) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions -- Delete only the staged replacement file.
			unlink( $temp );
			return null;
		}
		return $temp;
	}

	private function hashShape( string $hash ): bool {
		return (bool) preg_match( '/^[a-f0-9]{64}$/D', $hash );
	}
}
