<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Checks;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Findings\CheckResult;
use AmazingPlugins\Security\Findings\State;
use AmazingPlugins\Security\Scan\ScanContext;
use AmazingPlugins\Security\Scan\SecurityCheck;
use DateTimeImmutable;

final class FilesystemPermissionsCheck implements SecurityCheck {
	private const LABELS = array( 'root', 'configuration', 'content', 'uploads', 'plugins', 'themes', 'mu-plugins' );

	public function __construct( private readonly array $paths ) {
		if ( count( $paths ) > 7 || array_diff( array_keys( $paths ), self::LABELS ) ) {
			throw new \InvalidArgumentException( 'Unsupported permission target.' );
		}
	}

	public function id(): string {
		return 'filesystem-permissions';
	}

	public static function modeState( ?int $mode, bool $configuration ): string {
		if ( null === $mode || ! in_array( $mode & 0170000, array( 0100000, 0040000 ), true ) ) {
			return State::UNKNOWN;
		}
		return ( $mode & 0002 ) || ( $configuration && ( $mode & 0004 ) ) ? State::WARN : State::PASS;
	}

	public function run( ScanContext $context ): array {
		$rows = array();
		foreach ( $this->paths as $label => $path ) {
			$mode = null;
			if ( '/' === DIRECTORY_SEPARATOR && is_string( $path ) && strlen( $path ) <= 4096 && str_starts_with( $path, '/' ) ) {
				$path = rtrim( $path, '/' );
				clearstatcache( true, $path );
				// A canonical path equality check refuses links in the target or its ancestors.
				if ( realpath( $path ) === $path && ! is_link( $path ) ) {
					// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- An unavailable path becomes unknown without exposing host paths in warnings.
					$stat = @lstat( $path );
					$mode = is_array( $stat ) && is_int( $stat['mode'] ?? null ) ? $stat['mode'] : null;
				}
			}
			$state   = self::modeState( $mode, 'configuration' === $label );
			$summary = State::UNKNOWN === $state ? 'Mode bits unavailable or target unsupported. Ask the host to review this location.' : ( State::WARN === $state ? 'Review world-write permissions or world-readable configuration permissions with your host. Do not change modes blindly.' : 'No selected world-write or configuration world-read mode was found.' );
			$rows[]  = new CheckResult(
				$this->id(),
				$state,
				$summary . ' POSIX mode bits do not establish effective ACL permissions or public reachability.',
				'https://developer.wordpress.org/advanced-administration/security/hardening/',
				new DateTimeImmutable(),
				State::UNKNOWN === $state ? 'low' : 'medium',
				'partial',
				array(
					'location' => $label,
					'mode'     => State::UNKNOWN === $state ? null : sprintf( '%04o', $mode & 0777 ),
				),
				'permissions-' . $label
			);
		}
		return $rows;
	}

	public static function wordpressPaths(): array {
		$root   = rtrim( ABSPATH, '/' );
		$config = $root . '/wp-config.php';
		if ( ! file_exists( $config ) && ! file_exists( dirname( $root ) . '/wp-settings.php' ) ) {
			$config = dirname( $root ) . '/wp-config.php';
		}
		$upload = wp_upload_dir( null, false );
		$paths  = array(
			'root'          => $root,
			'configuration' => $config,
			'content'       => WP_CONTENT_DIR,
			'uploads'       => empty( $upload['error'] ) ? ( $upload['basedir'] ?? null ) : null,
			'plugins'       => WP_PLUGIN_DIR,
			'themes'        => get_theme_root(),
			'mu-plugins'    => WPMU_PLUGIN_DIR,
		);
		return $paths;
	}
}
