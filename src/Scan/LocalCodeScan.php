<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Scan;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\FileScan\FileScanCursor;
use AmazingPlugins\Security\FileScan\FileScanPlanBuilder;
use AmazingPlugins\Security\FileScan\FileScanRunner;
use AmazingPlugins\Security\Integrity\DiscoveryResult;
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
		// phpcs:ignore WordPress.WP.AlternativeFunctions.json_decode_json_decode -- Local code-scan record only. No release request is made.
		$data   = json_decode( $raw, true );
		$cursor = is_array( $data ) && 1 === ( $data['version'] ?? null ) && is_array( $data['cursor'] ?? null ) ? FileScanCursor::fromArray( $data['cursor'] ) : null;
		if ( ! $cursor instanceof FileScanCursor ) {
			$empty['stored'] = 'unknown';
			return $empty;
		}
		$found = self::suspected( $cursor );
		if ( $found > 0 ) {
			$stored = 'found';
		} elseif ( ! $cursor->finished ) {
			$stored = 'running';
		} else {
			$stored = $cursor->partial ? 'partial' : 'clean';
		}
		return array(
			'stored'  => $stored,
			'found'   => $found,
			'scanned' => min( 5000, $cursor->scanned ),
			'matches' => self::matches( $cursor ),
		);
	}

	public function advance(): string {
		$deadline = microtime( true ) + 12;
		do {
			$stored = $this->step();
			if ( 'running' !== $stored ) {
				return $stored;
			}
		} while ( microtime( true ) < $deadline );
		return self::snapshot()['stored'];
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
			$step = ( new FileScanRunner() )->step( $this->targets(), $cursor, new ScanContext( microtime( true ) + 6, 250 ) );
		} catch ( Throwable ) {
			return 'unknown';
		}
		$this->save( $step->cursor );
		return self::snapshot()['stored'];
	}

	private function save( FileScanCursor $cursor ): void {
		// phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Local code-scan record only. No release request is made.
		$encoded = json_encode(
			array(
				'version' => 1,
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
		return ( new FileScanPlanBuilder() )->build( new DiscoveryResult( array(), array(), '', false ), $this->plugins(), $this->themes(), $root );
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
