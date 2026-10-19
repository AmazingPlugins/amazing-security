<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Scan;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\FileScan\FileScanCursor;
use AmazingPlugins\Security\FileScan\FileScanPlanBuilder;
use AmazingPlugins\Security\FileScan\FileScanRunner;
use AmazingPlugins\Security\FileScan\FileScanTarget;
use AmazingPlugins\Security\Integrity\DiscoveryResult;
use AmazingPlugins\Security\Checks\LocalCodeCheck;
use AmazingPlugins\Security\Findings\CheckResult;
use AmazingPlugins\Security\Findings\FindingsRepository;
use Throwable;

/** Scans plugin, theme, and uploads PHP with the local patterns. It does not contact WordPress.org. */
final class LocalCodeScan {
	public const OPTION = 'amsec_local_code_state';

	/** @return array{stored: string, found: int, scanned: int, matches: string} */
	public static function snapshot(): array {
		$empty = array(
			'stored'  => 'none',
			'found'   => 0,
			'scanned' => 0,
			'matches' => '',
		);
		$raw   = function_exists( 'get_option' ) ? get_option( self::OPTION, null ) : null;
		if ( ! is_string( $raw ) || '' === $raw ) {
			return $empty;
		}
		$cursor = self::cursor();
		if ( ! $cursor instanceof FileScanCursor ) {
			$empty['stored'] = 'unknown';
			return $empty;
		}
		$found = self::suspected( $cursor );
		if ( ! $cursor->finished ) {
			$stored = 'running';
		} elseif ( $found > 0 ) {
			$stored = 'found';
		} else {
			$stored = $cursor->partial ? 'partial' : 'clean';
		}
		return array(
			'stored'  => $stored,
			'found'   => $found,
			'scanned' => min( FileScanCursor::MAX_FILES, $cursor->scanned ),
			'matches' => self::matches( $cursor ),
		);
	}

	public const TICK = 'amsec_local_code_tick';

	/** Entries read from one folder, and targets in one pass. Past either, the pass is marked partial. */
	private const DIR_ENTRIES = 2000;

	private bool $capped = false;

	/** When the current pass started, or 0 when there is none. */
	private static function started(): int {
		$raw = function_exists( 'get_option' ) ? get_option( self::OPTION, null ) : null;
		// phpcs:ignore WordPress.WP.AlternativeFunctions.json_decode_json_decode -- Local code-scan record only.
		$data = is_string( $raw ) ? json_decode( $raw, true ) : null;
		return is_array( $data ) && is_int( $data['started'] ?? null ) ? $data['started'] : 0;
	}

	public static function cursor(): ?FileScanCursor {
		$raw = function_exists( 'get_option' ) ? get_option( self::OPTION, null ) : null;
		if ( ! is_string( $raw ) || '' === $raw ) {
			return null;
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.json_decode_json_decode -- Local code-scan record only. No release request is made.
		$data = json_decode( $raw, true );
		return is_array( $data ) && 1 === ( $data['version'] ?? null ) && is_array( $data['cursor'] ?? null ) ? FileScanCursor::fromArray( $data['cursor'] ) : null;
	}

	/**
	 * A Scan continues a pass that started within the hour, so a big site can finish and its findings stay visible.
	 * Otherwise it starts fresh, so files changed since then are read again. The background tick only continues.
	 */
	public function advance( bool $fresh = true ): string {
		$cursor = self::cursor();
		if ( $fresh && ( null === $cursor || $cursor->finished || time() - self::started() > HOUR_IN_SECONDS ) ) {
			delete_option( self::OPTION );
		}
		$deadline = microtime( true ) + 12;
		do {
			// Findings do not end the pass; only a finished cursor or a failed step does.
			if ( 'unknown' === $this->step() || ( self::cursor()?->finished ?? true ) ) {
				return self::snapshot()['stored'];
			}
		} while ( microtime( true ) < $deadline );
		if ( function_exists( 'wp_next_scheduled' ) && ! wp_next_scheduled( self::TICK ) ) {
			wp_schedule_single_event( time() + 30, self::TICK );
		}
		return self::snapshot()['stored'];
	}

	public static function tick(): void {
		( new self() )->advance( false );
		if ( self::cursor()?->finished ) {
			self::refreshSaved();
		}
	}

	/** When the background pass ends, swap its "still running" row in the saved scan for the final result. */
	private static function refreshSaved(): void {
		$repository = new FindingsRepository();
		$run        = $repository->latest();
		if ( null === $run ) {
			return;
		}
		$kept = array_values( array_filter( $run->results, static fn( CheckResult $result ): bool => 'local-code' !== $result->checkId ) );
		$repository->save( new ScanRun( $run->startedAt, $run->finishedAt, array_merge( $kept, ( new LocalCodeCheck() )->run( new ScanContext() ) ), $run->partial ) );
	}

	private function step(): string {
		$raw    = get_option( self::OPTION, null );
		$cursor = null;
		if ( is_string( $raw ) && '' !== $raw ) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.json_decode_json_decode -- Local code-scan record only. No release request is made.
			$data   = json_decode( $raw, true );
			$cursor = is_array( $data ) && is_array( $data['cursor'] ?? null ) ? FileScanCursor::fromArray( $data['cursor'] ) : null;
		}
		if ( $cursor instanceof FileScanCursor && $cursor->finished ) {
			return self::snapshot()['stored'];
		}
		if ( ! $cursor instanceof FileScanCursor ) {
			$cursor = new FileScanCursor( function_exists( 'wp_generate_uuid4' ) ? wp_generate_uuid4() : bin2hex( random_bytes( 16 ) ) );
		}
		try {
			$targets = $this->targets();
			$step    = ( new FileScanRunner() )->step( $targets, $cursor, new ScanContext( microtime( true ) + 6, 250 ) );
		} catch ( Throwable ) {
			return 'unknown';
		}
		// A capped folder listing means some files were never offered to the scan.
		if ( $this->capped ) {
			$step->cursor->partial = true;
		}
		$this->save( $step->cursor );
		return self::snapshot()['stored'];
	}

	private function save( FileScanCursor $cursor ): void {
		// phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Local code-scan record only. No release request is made.
		$encoded = json_encode(
			array(
				'version' => 1,
				'started' => 0 === self::started() ? time() : self::started(),
				'cursor'  => $cursor->toArray(),
			)
		);
		if ( ! is_string( $encoded ) ) {
			return;
		}
		update_option( self::OPTION, $encoded, false );
	}

	/** @return array<int, \AmazingPlugins\Security\FileScan\FileScanTarget> */
	private function targets(): array {
		$uploads = function_exists( 'wp_upload_dir' ) ? wp_upload_dir( null, false ) : array();
		$root    = is_array( $uploads ) && empty( $uploads['error'] ) && is_string( $uploads['basedir'] ?? null ) ? $uploads['basedir'] : '';
		$targets = ( new FileScanPlanBuilder() )->build( new DiscoveryResult( array(), array(), '', false ), $this->plugins(), $this->themes(), $root );
		if ( defined( 'WPMU_PLUGIN_DIR' ) && is_dir( WPMU_PLUGIN_DIR ) ) {
			$targets[] = new FileScanTarget( 'mu-plugins', 'plugin', WPMU_PLUGIN_DIR );
		}
		// Folders WordPress does not list as a plugin or theme, for example a dropped folder without a header.
		$listed = array();
		foreach ( $targets as $target ) {
			$listed[ rtrim( $target->root, '/' ) . '/' . ( $target->singleFile ?? '' ) ] = true;
		}
		foreach ( array(
			'plugin' => defined( 'WP_PLUGIN_DIR' ) ? WP_PLUGIN_DIR : '',
			'theme'  => function_exists( 'get_theme_root' ) ? get_theme_root() : '',
		) as $kind => $dir ) {
			$dir = rtrim( $dir, '/' );
			foreach ( $this->entries( $dir ) as $name ) {
				if ( is_link( $dir . '/' . $name ) ) {
					continue;
				}
				if ( is_dir( $dir . '/' . $name ) && ! isset( $listed[ $dir . '/' . $name . '/' ] ) ) {
					$targets[] = new FileScanTarget( 'unlisted:' . $name, $kind, $dir . '/' . $name );
				} elseif ( is_file( $dir . '/' . $name ) && preg_match( '/\.(?:php|phtml|php[0-9]+|pht)$/iD', $name ) && ! isset( $listed[ $dir . '/' . $name ] ) ) {
					$targets[] = new FileScanTarget( 'unlisted:' . $name, $kind, $dir, null, $name );
				}
			}
		}
		// Loose PHP in the site root and in wp-content is a common hiding place. Folders there are covered above or by the release check.
		foreach ( array(
			'site'    => defined( 'ABSPATH' ) ? ABSPATH : '',
			'content' => defined( 'WP_CONTENT_DIR' ) ? WP_CONTENT_DIR : '',
		) as $kind => $dir ) {
			$dir   = rtrim( $dir, '/' );
			$names = array_values( preg_grep( '/\.(?:php|phtml|php[0-9]+|pht)$/iD', $this->entries( $dir ) ) );
			foreach ( $names as $name ) {
				if ( is_file( $dir . '/' . $name ) ) {
					$targets[] = new FileScanTarget( $kind . ':' . $name, $kind, $dir, null, $name );
				}
			}
		}
		if ( count( $targets ) > FileScanCursor::MAX_TARGETS ) {
			$this->capped = true;
			$targets      = array_slice( $targets, 0, FileScanCursor::MAX_TARGETS );
		}
		return $targets;
	}

	/**
	 * Up to DIR_ENTRIES names from one folder, sorted, read without loading the whole listing.
	 *
	 * @return list<string>
	 */
	private function entries( string $dir ): array {
		$names  = array();
		$handle = '' !== $dir && is_dir( $dir ) ? opendir( $dir ) : false;
		if ( false === $handle ) {
			return $names;
		}
		// phpcs:ignore Generic.CodeAnalysis.AssignmentInCondition.FoundInWhileCondition -- Standard readdir loop.
		while ( false !== ( $name = readdir( $handle ) ) ) {
			if ( '.' === $name || '..' === $name ) {
				continue;
			}
			if ( count( $names ) >= self::DIR_ENTRIES ) {
				$this->capped = true;
				break;
			}
			$names[] = $name;
		}
		closedir( $handle );
		sort( $names, SORT_STRING );
		return $names;
	}

	private function plugins(): array {
		if ( ! function_exists( 'get_plugins' ) && defined( 'ABSPATH' ) ) {
			$plugin_file = ABSPATH . 'wp-admin/includes/plugin.php';
			if ( is_file( $plugin_file ) ) {
				require_once $plugin_file;
			}
		}
		if ( ! function_exists( 'get_plugins' ) || ! defined( 'WP_PLUGIN_DIR' ) ) {
			return array();
		}
		$rows = array();
		foreach ( get_plugins() as $file => $data ) {
			if ( ! is_string( $file ) ) {
				continue;
			}
			$slug   = dirname( $file );
			$rows[] = array(
				'slug'        => '.' === $slug ? basename( $file ) : $slug,
				'version'     => is_array( $data ) ? (string) ( $data['Version'] ?? '' ) : '',
				'root'        => '.' === $slug ? WP_PLUGIN_DIR : WP_PLUGIN_DIR . '/' . $slug,
				'update_uri'  => '',
				'single_file' => '.' === $slug ? basename( $file ) : null,
				'local_only'  => true,
			);
		}
		return $rows;
	}

	private function themes(): array {
		if ( ! function_exists( 'wp_get_themes' ) ) {
			return array();
		}
		$rows = array();
		foreach ( wp_get_themes() as $slug => $theme ) {
			if ( ! is_string( $slug ) || ! is_object( $theme ) || ! method_exists( $theme, 'get' ) || ! method_exists( $theme, 'get_stylesheet_directory' ) ) {
				continue;
			}
			$rows[] = array(
				'slug'       => $slug,
				'version'    => (string) $theme->get( 'Version' ),
				'root'       => (string) $theme->get_stylesheet_directory(),
				'update_uri' => '',
				'local_only' => true,
			);
		}
		return $rows;
	}

	private static function matches( FileScanCursor $cursor ): string {
		$lines = array();
		foreach ( $cursor->findings as $finding ) {
			if ( ! is_array( $finding ) || 'warn' !== ( $finding['state'] ?? '' ) || 'suspected' !== ( $finding['kind'] ?? '' ) ) {
				continue;
			}
			$path = is_string( $finding['path'] ?? null ) ? $finding['path'] : '';
			$rule = is_string( $finding['rule_id'] ?? null ) ? $finding['rule_id'] : '';
			$line = is_int( $finding['line'] ?? null ) ? $finding['line'] : 0;
			$path = preg_replace( '/[^A-Za-z0-9._\/-]/', '', $path ) ?? '';
			if ( strlen( $path ) > 80 ) {
				$path = substr( $path, 0, 80 );
			}
			if ( 1 !== preg_match( '/^AS-[A-Z]+-\d{3}$/D', $rule ) ) {
				$rule = '';
			}
			$lines[] = trim( $path . ' line ' . $line . ( '' !== $rule ? ' ' . $rule : '' ) );
			if ( 3 === count( $lines ) ) {
				break;
			}
		}
		$text  = implode( '; ', $lines );
		$extra = self::suspected( $cursor ) - count( $lines );
		if ( $extra > 0 ) {
			$text .= '; ' . $extra . ' more';
		}
		return strlen( $text ) > 300 ? substr( $text, 0, 300 ) : $text;
	}

	private static function suspected( FileScanCursor $cursor ): int {
		$found = 0;
		foreach ( $cursor->findings as $finding ) {
			if ( is_array( $finding ) && 'warn' === ( $finding['state'] ?? '' ) && 'suspected' === ( $finding['kind'] ?? '' ) ) {
				++$found;
			}
		}
		return min( 250, $found );
	}
}
