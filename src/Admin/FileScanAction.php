<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Alerts\WordPressAlertNotifier;
use AmazingPlugins\Security\FileScan\FileScanCursor;
use AmazingPlugins\Security\FileScan\FileScanPlanBuilder;
use AmazingPlugins\Security\FileScan\FileScanReport;
use AmazingPlugins\Security\FileScan\FileScanRunner;
use AmazingPlugins\Security\FileScan\FileScanStep;
use AmazingPlugins\Security\FileScan\WordPressFileScanStore;
use AmazingPlugins\Security\Integrity\TargetDiscovery;
use AmazingPlugins\Security\Integrity\ThemeArchiveParser;
use AmazingPlugins\Security\Integrity\WorkerLock;
use AmazingPlugins\Security\Integrity\WordPressHttpClient;
use AmazingPlugins\Security\Integrity\WordPressOptions;
use AmazingPlugins\Security\Integrity\WordPressOrgManifestProvider;
use AmazingPlugins\Security\Integrity\WordPressOrgThemeManifestProvider;
use AmazingPlugins\Security\Scan\ScanContext;
use AmazingPlugins\Security\Schedule\SuiteCycle;
use Throwable;

final class FileScanAction {
	public function start(): void {
		$this->authorize( 'amazing_security_file_scan_start' );
		$store  = new WordPressFileScanStore( new WordPressOptions() );
		$scanId = wp_generate_uuid4();
		$cursor = new FileScanCursor( $scanId );
		if ( ! $store->begin( $scanId, $cursor ) ) {
			$this->redirect( true );
		}
		$this->redirect( $this->execute( $store, $cursor, true ) );
	}

	public function resume(): void {
		$this->authorize( 'amazing_security_file_scan_resume' );
		$store    = new WordPressFileScanStore( new WordPressOptions() );
		$progress = $store->latestProgress();
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce was checked above.
		$scanId = isset( $_POST['scan_id'] ) && is_string( $_POST['scan_id'] ) ? sanitize_text_field( wp_unslash( $_POST['scan_id'] ) ) : '';
		if ( null === $progress || $progress->finished || ! hash_equals( $progress->cursor->scanId, $scanId ) ) {
			$this->redirect( true );
		}
		$this->redirect( $this->execute( $store, $progress->cursor, false ) );
	}

	public function scheduled(): void {
		$options = new WordPressOptions();
		$cycle   = new SuiteCycle( $options );
		if ( ! $cycle->claim( 'files', time() ) ) {
			return;
		}
		$store    = new WordPressFileScanStore( $options );
		$progress = $store->latestProgress();
		if ( null !== $progress && ! $progress->finished ) {
			$error = $this->execute( $store, $progress->cursor, false );
		} else {
			$scanId = wp_generate_uuid4();
			$cursor = new FileScanCursor( $scanId );
			if ( ! $store->begin( $scanId, $cursor ) ) {
				if ( $cycle->retry( 'files', time() ) ) {
					$this->scheduleNext( 300 );
				}
				return;
			}
			$error = $this->execute( $store, $cursor, true );
		}
		$progress = $store->latestProgress();
		if ( $error ) {
			if ( null !== $progress && $progress->finished ) {
				$cycle->fail( 'files', time() );
			} elseif ( $cycle->retry( 'files', time() ) ) {
				$this->scheduleNext( 300 );
			}
			return;
		}
		if ( null === $progress ) {
			$cycle->complete( time() );
			return;
		}
		if ( ! $progress->finished ) {
			if ( $cycle->continueStage( 'files', time() ) ) {
				$this->scheduleNext();
			}
			return;
		}
		if ( $progress->cursor->partial ) {
			$cycle->fail( 'files', time() );
		} else {
			$cycle->complete( time() );
		}
	}

	private function authorize( string $nonceAction ): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to run a file scan.', 'amazing-security' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( $nonceAction );
	}

	private function execute( WordPressFileScanStore $store, FileScanCursor $cursor, bool $isStart ): bool {
		$options = new WordPressOptions();
		$lock    = new WorkerLock( $options, 'amazing_security_file_scan_worker_lock' );
		if ( ! $lock->acquire( $cursor->scanId ) ) {
			return true;
		}
		$error = false;
		try {
			$started          = microtime( true );
			$plugins          = $this->plugins();
			$themes           = $this->themes();
			$client           = new WordPressHttpClient();
			$discovery        = ( new TargetDiscovery( new WordPressOrgManifestProvider( $client ), new WordPressOrgThemeManifestProvider( $client, new ThemeArchiveParser() ) ) )->discover( $this->coreVersion(), $this->coreLocale(), ABSPATH, $this->manifestPlugins( $plugins ), $themes );
			$cursor->elapsed += microtime( true ) - $started;
			if ( $isStart ) {
				$cursor->partial = $discovery->partial;
				foreach ( $discovery->findings as $finding ) {
					++$cursor->unknown;
					if ( count( $cursor->findings ) < 250 ) {
						$cursor->findings[] = array(
							'id'        => $finding->findingId ?? substr( hash( 'sha256', (string) ( $finding->evidence['package'] ?? '' ) ), 0, 32 ),
							'state'     => 'inconclusive',
							'kind'      => 'package',
							'package'   => $finding->evidence['package'] ?? '',
							'path'      => '',
							'rule_id'   => '',
							'version'   => '',
							'line'      => 0,
							'reason'    => $finding->evidence['reason'] ?? '',
							'summary'   => 'Published release could not be verified.',
							'tested_at' => $finding->testedAt->format( 'c' ),
						);
					} else {
						++$cursor->omitted;
					}
				}
			}
			$uploads = wp_upload_dir();
			$targets = ( new FileScanPlanBuilder() )->build( $discovery, $plugins, $themes, (string) ( $uploads['basedir'] ?? '' ) );
			$step    = ( new FileScanRunner() )->step( $targets, $cursor, new ScanContext() );
			$store->saveProgress( $cursor->scanId, $step );
			if ( $step->finished ) {
				$report = FileScanReport::fromCursor( $step->cursor );
				$store->complete( $cursor->scanId, $report );
				try {
					( new WordPressAlertNotifier() )->create()->files( $report, time() );
				} catch ( Throwable ) {
					// Mail cannot undo a completed file report.
					return false;
				}
			}
		} catch ( Throwable $failure ) {
			$error            = true;
			$cursor->partial  = true;
			$cursor->finished = true;
			try {
				$store->saveProgress( $cursor->scanId, new FileScanStep( $cursor, true ) );
			} catch ( Throwable $ignored ) {
				// Keep the last completed report if progress cannot be saved.
				$error = true;
			}
		} finally {
			$lock->release();
		}
		return $error;
	}

	private function scheduleNext( int $delay = 60 ): void {
		if ( ! wp_next_scheduled( 'amsec_file_tick' ) ) {
			wp_schedule_single_event( time() + $delay, 'amsec_file_tick' );
		}
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
			$slug = dirname( $file );
			if ( '.' === $slug || ! preg_match( '/^[a-z0-9]+(?:-[a-z0-9]+)*$/D', $slug ) ) {
				$plugins[] = array(
					'slug'        => '.' === $slug ? basename( $file ) : $slug,
					'version'     => (string) ( $data['Version'] ?? '' ),
					'root'        => '.' === $slug ? WP_PLUGIN_DIR : WP_PLUGIN_DIR . '/' . $slug,
					'update_uri'  => 'unsupported_local_path',
					'single_file' => '.' === $slug ? basename( $file ) : null,
					'local_only'  => true,
				);
				continue;
			}
			$plugins[] = array(
				'slug'       => $slug,
				'version'    => (string) ( $data['Version'] ?? '' ),
				'root'       => WP_PLUGIN_DIR . '/' . $slug,
				'update_uri' => (string) ( $data['UpdateURI'] ?? '' ),
				'local_only' => plugin_basename( AMAZING_SECURITY_FILE ) === $file,
			);
		}
		return $plugins;
	}

	private function manifestPlugins( array $plugins ): array {
		return array_values( array_filter( $plugins, static fn( array $row ): bool => ! (bool) ( $row['local_only'] ?? false ) && 'unsupported_local_path' !== ( $row['update_uri'] ?? '' ) ) );
	}

	private function themes(): array {
		$themes = array();
		foreach ( wp_get_themes() as $slug => $theme ) {
			$themes[] = array(
				'slug'       => (string) $slug,
				'version'    => (string) $theme->get( 'Version' ),
				'root'       => $theme->get_stylesheet_directory(),
				'update_uri' => (string) $theme->get( 'UpdateURI' ),
				'child'      => $theme->parent() instanceof \WP_Theme,
			);
		}
		return $themes;
	}

	private function redirect( bool $error ): never {
		wp_safe_redirect( admin_url( 'admin.php?page=amsec-file-checks' . ( $error ? '&amazing_security_file_scan_error=1' : '' ) . '#amsec-file-scan' ) );
		exit;
	}
}
