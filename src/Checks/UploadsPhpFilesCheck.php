<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Checks;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Findings\CheckResult;
use AmazingPlugins\Security\Findings\State;
use AmazingPlugins\Security\Scan\ScanContext;
use AmazingPlugins\Security\Scan\SecurityCheck;
use Closure;
use DirectoryIterator;
use DateTimeImmutable;
use DateTimeZone;
use Throwable;

/** Looks for PHP files in the uploads folder. It does not open, run, or delete them. */
final class UploadsPhpFilesCheck implements SecurityCheck {
	private const SOURCE = 'https://developer.wordpress.org/advanced-administration/security/hardening/';
	private readonly Closure $readKind;

	public function __construct( ?callable $readKind = null ) {
		$this->readKind = Closure::fromCallable( $readKind ?? array( self::class, 'wordpressKind' ) );
	}

	public function id(): string {
		return 'uploads-php-files';
	}

	public static function decide( string $kind ): string {
		return match ( $kind ) {
			'present' => 'warn',
			'absent' => 'pass',
			default => 'unknown',
		};
	}

	public static function wordpressKind(): string {
		if ( ! function_exists( 'wp_upload_dir' ) ) {
			return 'unknown';
		}
		$uploads = wp_upload_dir( null, false );
		$root    = is_array( $uploads ) && empty( $uploads['error'] ) && is_string( $uploads['basedir'] ?? null ) ? $uploads['basedir'] : '';
		if ( '' === $root || is_link( $root ) || ! is_dir( $root ) ) {
			return 'unknown';
		}
		$real = realpath( $root );
		return is_string( $real ) ? self::walk( $real ) : 'unknown';
	}

	private static function walk( string $root ): string {
		$pending = array( $root );
		$seen    = 0;
		while ( array() !== $pending ) {
			$directory = array_pop( $pending );
			if ( ! is_string( $directory ) || is_link( $directory ) || ! is_dir( $directory ) ) {
				return 'unknown';
			}
			try {
				$items = new DirectoryIterator( $directory );
			} catch ( Throwable ) {
				return 'unknown';
			}
			foreach ( $items as $item ) {
				if ( $item->isDot() ) {
					continue;
				}
				if ( ++$seen > 4000 ) {
					return 'partial';
				}
				if ( $item->isLink() ) {
					continue;
				}
				if ( $item->isFile() && 1 === preg_match( '/\.(?:php|phtml|php5|phar)$/iD', $item->getFilename() ) ) {
					return 'present';
				}
				if ( $item->isDir() ) {
					$pending[] = $item->getPathname();
				}
			}
		}
		return 'absent';
	}

	public function run( ScanContext $context ): array {
		unset( $context );
		$kind    = (string) ( $this->readKind )();
		$state   = self::decide( $kind );
		$summary = match ( $state ) {
			'warn' => __( 'A PHP file is in the uploads folder. This check does not open, run, or delete it.', 'amazing-security' ),
			'pass' => __( 'No PHP file was found in the uploads folder. This check does not open, run, or delete files.', 'amazing-security' ),
			default => __( 'The uploads folder could not be fully checked for PHP files. This check does not open, run, or delete files.', 'amazing-security' ),
		};
		return array(
			new CheckResult( $this->id(), 'warn' === $state ? State::WARN : ( 'pass' === $state ? State::PASS : State::UNKNOWN ), $summary, self::SOURCE, new DateTimeImmutable( 'now', new DateTimeZone( 'UTC' ) ), 'medium', 'unknown' === $state ? 'unavailable' : 'complete', array( 'kind' => $kind ) ),
		);
	}
}
