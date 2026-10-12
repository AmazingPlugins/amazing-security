<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Repair;

use AmazingPlugins\Security\Integrity\WordPressHttpClient;
use AmazingPlugins\Security\Integrity\WordPressIntegrityStore;
use AmazingPlugins\Security\Integrity\WordPressOptions;
use AmazingPlugins\Security\Integrity\WordPressOrgManifestProvider;

final class WordPressPluginRepair {
	public function preview( string $findingId ): ?RepairPreview {
		$candidate = $this->candidate( $findingId );
		if ( null === $candidate ) {
			return null;
		}
		$root = $this->installedRoot( $candidate->slug, $candidate->version );
		if ( null === $root ) {
			return null;
		}
		$atomic = new AtomicPluginRepair( $root, sys_get_temp_dir() );
		if ( $candidate->observedSha256 !== $atomic->currentSha256( $candidate->relativePath ) ) {
			return null;
		}
		$http        = new WordPressHttpClient();
		$replacement = ( new PluginRepairSource( new WordPressOrgManifestProvider( $http ), $http ) )->fetch( $candidate );
		return null === $replacement ? null : new RepairPreview( $candidate, $replacement, $root );
	}

	public function apply( RepairPreview $preview, string $approvedBefore, string $approvedAfter ): ?RepairReceipt {
		if ( ! hash_equals( $preview->candidate->observedSha256, $approvedBefore ) || ! hash_equals( $preview->replacement->sha256, $approvedAfter ) ) {
			return null;
		}
		$backupRoot = $this->backupRoot();
		if ( null === $backupRoot ) {
			return null;
		}
		$key = $this->receiptOption( $preview->candidate->findingId );
		$this->clearStalePending( $key );
		if ( ! ( new WordPressOptions() )->add(
			$key,
			wp_json_encode(
				array(
					'status' => 'pending',
					'at'     => time(),
				)
			)
		) ) {
			return null;
		}
		$atomic = new AtomicPluginRepair( $preview->root, $backupRoot, beforeReplace: fn( RepairReceipt $receipt ): bool => $this->saveReceipt( $key, $preview, $receipt, 'prepared' ) );
		try {
			$receipt = $atomic->apply( $preview->candidate->relativePath, $approvedBefore, $approvedAfter, $preview->replacement );
		} catch ( RepairVerificationFailure $failure ) {
			$this->saveReceipt( $key, $preview, $failure->receipt, 'needs_recovery' );
			return null;
		}
		if ( null === $receipt ) {
			delete_option( $key );
			return null;
		}
		if ( ! $this->saveReceipt( $key, $preview, $receipt, 'applied' ) ) {
			// Keep the prepared receipt and backup usable while database writes are unavailable.
			// An operator can recover using the exact observed file hash once storage is healthy.
			return null;
		}
		return $receipt;
	}

	private function saveReceipt( string $key, RepairPreview $preview, RepairReceipt $receipt, string $status ): bool {
		$data = array(
			'status'     => $status,
			'slug'       => $preview->candidate->slug,
			'version'    => $preview->candidate->version,
			'receipt'    => $receipt->toArray(),
			'created_at' => time(),
		);
		return update_option( $key, wp_json_encode( $data ), false );
	}

	public function receipt( string $findingId ): ?array {
		$raw  = get_option( $this->receiptOption( $findingId ), null );
		$data = is_string( $raw ) ? json_decode( $raw, true ) : null;
		return is_array( $data ) && in_array( $data['status'] ?? null, array( 'prepared', 'applied', 'needs_recovery' ), true ) && isset( $data['slug'], $data['version'], $data['receipt'] ) && is_array( $data['receipt'] ) ? $data : null;
	}

	public function rollback( string $findingId ): bool {
		$data = $this->receipt( $findingId );
		if ( null === $data || 'applied' !== $data['status'] ) {
			return false;
		}
		$receipt    = RepairReceipt::fromArray( $data['receipt'] );
		$root       = $this->installedRoot( (string) $data['slug'], (string) $data['version'] );
		$backupRoot = $this->backupRoot();
		if ( null === $receipt || null === $root || null === $backupRoot || ! ( new AtomicPluginRepair( $root, $backupRoot ) )->rollback( $receipt ) ) {
			return false;
		}
		delete_option( $this->receiptOption( $findingId ) );
		return true;
	}

	public function recover( string $findingId, string $observedSha256 ): bool {
		$data = $this->receipt( $findingId );
		if ( null === $data || ! in_array( $data['status'], array( 'prepared', 'needs_recovery' ), true ) || ! preg_match( '/^[a-f0-9]{64}$/D', $observedSha256 ) ) {
			return false;
		}
		$receipt    = RepairReceipt::fromArray( $data['receipt'] );
		$root       = $this->installedRoot( (string) $data['slug'], (string) $data['version'] );
		$backupRoot = $this->backupRoot();
		if ( null === $receipt || null === $root || null === $backupRoot || ! ( new AtomicPluginRepair( $root, $backupRoot ) )->recover( $receipt, $observedSha256 ) ) {
			return false;
		}
		delete_option( $this->receiptOption( $findingId ) );
		return true;
	}

	public function canRollback( string $findingId ): bool {
		$data = $this->receipt( $findingId );
		if ( null === $data || 'applied' !== $data['status'] ) {
			return false;
		}
		$receipt = RepairReceipt::fromArray( $data['receipt'] );
		$root    = $this->installedRoot( (string) $data['slug'], (string) $data['version'] );
		// phpcs:ignore WordPress.PHP.YodaConditions.NotYoda -- Both hashes are dynamic.
		return null !== $receipt && null !== $root && $receipt->afterSha256 === ( new AtomicPluginRepair( $root, sys_get_temp_dir() ) )->currentSha256( $receipt->relativePath );
	}

	public function retire( string $findingId ): bool {
		$data = $this->receipt( $findingId );
		if ( null === $data || 'applied' !== $data['status'] ) {
			return false;
		}
		$receipt    = RepairReceipt::fromArray( $data['receipt'] );
		$candidate  = $this->candidate( $findingId, (int) ( $data['created_at'] ?? 0 ) );
		$root       = $this->installedRoot( (string) $data['slug'], (string) $data['version'] );
		$backupRoot = $this->backupRoot();
		if ( null === $receipt || null === $candidate || null === $root || null === $backupRoot || $candidate->slug !== $data['slug'] || $candidate->version !== $data['version'] || $candidate->relativePath !== $receipt->relativePath || $candidate->observedSha256 === $receipt->afterSha256 ) {
			return false;
		}
		$atomic = new AtomicPluginRepair( $root, $backupRoot );
		if ( $candidate->observedSha256 !== $atomic->currentSha256( $receipt->relativePath ) || ! $atomic->discardBackup( $receipt ) ) {
			return false;
		}
		delete_option( $this->receiptOption( $findingId ) );
		return true;
	}

	private function candidate( string $findingId, int $after = 0 ): ?RepairCandidate {
		$store    = new WordPressIntegrityStore( new WordPressOptions() );
		$progress = $store->latestProgress();
		if ( null !== $progress && $progress->finished ) {
			$recent    = array_values( array_filter( $progress->cursor->findings, static fn( mixed $finding ): bool => $finding->testedAt->getTimestamp() > $after ) );
			$candidate = RepairCandidate::fromFindings( $recent, $findingId );
			if ( null !== $candidate ) {
				return $candidate;
			}
		}
		$completed = $store->latestCompleted();
		$recent    = null === $completed ? array() : array_values( array_filter( $completed->results, static fn( mixed $finding ): bool => $finding->testedAt->getTimestamp() > $after ) );
		return RepairCandidate::fromFindings( $recent, $findingId );
	}

	private function installedRoot( string $slug, string $version ): ?string {
		if ( 'amazing-security' === $slug || ! preg_match( '/^[a-z0-9]+(?:-[a-z0-9]+)*$/D', $slug ) || ! preg_match( '/^[0-9]+(?:\.[0-9A-Za-z-]+)*$/D', $version ) ) {
			return null;
		}
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$found = false;
		foreach ( get_plugins() as $file => $data ) {
			// phpcs:ignore WordPress.PHP.YodaConditions.NotYoda -- Both operands are dynamic package identities.
			if ( $slug !== dirname( $file ) ) {
				continue;
			}
			// phpcs:ignore WordPress.PHP.YodaConditions.NotYoda -- Installed and scanned versions are both dynamic.
			if ( $version !== (string) ( $data['Version'] ?? '' ) || '' !== (string) ( $data['UpdateURI'] ?? '' ) ) {
				return null;
			}
			$found = true;
		}
		return $found ? WP_PLUGIN_DIR . '/' . $slug : null;
	}

	private function backupRoot(): ?string {
		$parent  = realpath( sys_get_temp_dir() );
		$site    = realpath( ABSPATH );
		$content = realpath( WP_CONTENT_DIR );
		if ( false === $parent || false === $site || false === $content || str_starts_with( $parent . '/', $site . '/' ) || str_starts_with( $parent . '/', $content . '/' ) ) {
			return null;
		}
		$path = $parent . '/amsec-backups-' . substr( hash( 'sha256', $site ), 0, 16 );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_mkdir -- Private backup directory is outside the served site and requires direct filesystem access.
		if ( ! is_dir( $path ) && false === mkdir( $path, 0700 ) ) {
			return null;
		}
		$mode = fileperms( $path );
		if ( false === $mode || 0 !== ( $mode & 0077 ) ) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions -- The backup directory must be private before any site file is changed.
			if ( ! chmod( $path, 0700 ) ) {
				return null;
			}
			clearstatcache( true, $path );
			if ( 0 !== ( fileperms( $path ) & 0077 ) ) {
				return null;
			}
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- Direct filesystem is required for atomic repair.
		return ! is_link( $path ) && is_dir( $path ) && is_writable( $path ) ? $path : null;
	}

	/** A request that died before saving its receipt leaves a pending row that would block every later repair of that finding. */
	private function clearStalePending( string $key ): void {
		$raw = get_option( $key, null );
		if ( ! is_string( $raw ) ) {
			return;
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_decode -- Own receipt row.
		$data = json_decode( $raw, true );
		if ( is_array( $data ) && 'pending' === ( $data['status'] ?? null ) && time() - (int) ( $data['at'] ?? 0 ) > 600 ) {
			delete_option( $key );
		}
	}

	private function receiptOption( string $findingId ): string {
		return 'amsec_repair_' . substr( hash( 'sha256', $findingId ), 0, 32 );
	}
}
