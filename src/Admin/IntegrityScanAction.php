<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

use AmazingPlugins\Security\Integrity\FileReader;
use AmazingPlugins\Security\Integrity\CompletedIntegrityReport;
use AmazingPlugins\Security\Integrity\IntegrityCursor;
use AmazingPlugins\Security\Integrity\IntegrityRunner;
use AmazingPlugins\Security\Integrity\IntegrityStep;
use AmazingPlugins\Security\Integrity\TargetDiscovery;
use AmazingPlugins\Security\Integrity\WorkerLock;
use AmazingPlugins\Security\Integrity\WordPressHttpClient;
use AmazingPlugins\Security\Integrity\WordPressIntegrityStore;
use AmazingPlugins\Security\Integrity\WordPressOptions;
use AmazingPlugins\Security\Integrity\WordPressOrgManifestProvider;
use AmazingPlugins\Security\Scan\ScanContext;
use DateTimeImmutable;
use Throwable;

final class IntegrityScanAction {
	public function start(): void {
		$this->authorize( 'amazing_security_integrity_start' );
		$store  = new WordPressIntegrityStore( new WordPressOptions() );
		$scanId = wp_generate_uuid4();
		$cursor = new IntegrityCursor( $scanId, startedAt: new DateTimeImmutable() );
		if ( ! $store->begin( $scanId, $cursor ) ) {
			$this->redirect( true );
		}
		$this->execute( $store, $cursor, true );
	}

	public function resume(): void {
		$this->authorize( 'amazing_security_integrity_resume' );
		$store    = new WordPressIntegrityStore( new WordPressOptions() );
		$progress = $store->latestProgress();
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verified above.
		$scanId = isset( $_POST['scan_id'] ) && is_string( $_POST['scan_id'] ) ? sanitize_text_field( wp_unslash( $_POST['scan_id'] ) ) : '';
		if ( null === $progress || $progress->finished || ! hash_equals( $progress->cursor->scanId, $scanId ) ) {
			$this->redirect( true );
		}
		$this->execute( $store, $progress->cursor, false );
	}

	private function authorize( string $nonceAction ): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to run an integrity scan.', 'amazing-security' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( $nonceAction );
	}

	private function execute( WordPressIntegrityStore $store, IntegrityCursor $cursor, bool $isStart ): void {
		$workerLock = new WorkerLock( new WordPressOptions() );
		if ( ! $workerLock->acquire( $cursor->scanId ) ) {
			$this->redirect( true );
		}
		$error = false;
		try {
			$started          = microtime( true );
			$discovery        = ( new TargetDiscovery( new WordPressOrgManifestProvider( new WordPressHttpClient() ) ) )->discover( $this->coreVersion(), $this->coreLocale(), ABSPATH, $this->plugins() );
			$cursor->elapsed += microtime( true ) - $started;
			if ( $isStart ) {
				$cursor->targetSignature = $discovery->signature;
				$cursor->findings        = array_slice( $discovery->findings, 0, 250 );
				$cursor->partial         = $discovery->partial || count( $discovery->findings ) > 250;
			}
			if ( ! $isStart && ! hash_equals( $cursor->targetSignature, $discovery->signature ) ) {
				$cursor->partial = true;
				$store->saveProgress( $cursor->scanId, new IntegrityStep( $cursor, true ) );
			} else {
				$step = ( new IntegrityRunner( new FileReader() ) )->step( $discovery->targets, $cursor, new ScanContext() );
				$store->saveProgress( $cursor->scanId, $step );
				if ( $step->finished && ! $step->cursor->partial ) {
					$store->complete( $cursor->scanId, ( new CompletedIntegrityReport() )->fromCursor( $cursor ) );
				}
			}
		} catch ( Throwable $failure ) {
			$error           = true;
			$cursor->partial = true;
			try {
				$store->saveProgress( $cursor->scanId, new IntegrityStep( $cursor, true ) );
			} catch ( Throwable $ignored ) {
				// Keep the last completed report if progress could not be persisted.
				$error = true;
			}
		} finally {
			$workerLock->release();
		}
		$this->redirect( $error );
	}

	private function coreVersion(): string {
		global $wp_version;
		return (string) $wp_version;
	}

	private function coreLocale(): string {
		global $wp_local_package;
		return isset( $wp_local_package ) && is_string( $wp_local_package ) && '' !== $wp_local_package ? $wp_local_package : 'en_US';
	}

	private function plugins(): array {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$plugins = array();
		foreach ( get_plugins() as $file => $data ) {
			if ( str_starts_with( $file, 'amazing-security/' ) ) {
				continue;
			}
			$slug = dirname( $file );
			if ( '.' === $slug || ! preg_match( '/^[a-z0-9]+(?:-[a-z0-9]+)*$/D', $slug ) ) {
				$plugins[] = array(
					'slug'       => basename( $file ),
					'version'    => (string) ( $data['Version'] ?? '' ),
					'root'       => WP_PLUGIN_DIR,
					'update_uri' => 'unsupported_local_path',
				);
				continue;
			}
			$plugins[] = array(
				'slug'       => $slug,
				'version'    => (string) ( $data['Version'] ?? '' ),
				'root'       => WP_PLUGIN_DIR . '/' . $slug,
				'update_uri' => (string) ( $data['UpdateURI'] ?? '' ),
			);
		}
		return $plugins;
	}

	private function redirect( bool $error ): never {
		wp_safe_redirect( admin_url( 'admin.php?page=amazing-security' . ( $error ? '&amazing_security_integrity_error=1' : '' ) ) );
		exit;
	}
}
