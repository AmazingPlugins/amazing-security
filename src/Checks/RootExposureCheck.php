<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Checks;

use AmazingPlugins\Security\Findings\CheckResult;
use AmazingPlugins\Security\Findings\State;
use AmazingPlugins\Security\Scan\ScanContext;
use AmazingPlugins\Security\Scan\SecurityCheck;
use Closure;
use DateTimeImmutable;
use DateTimeZone;

/** Reports a root .env file or .git directory. It does not read or delete either one. */
final class RootExposureCheck implements SecurityCheck {
	private const SOURCE = 'https://developer.wordpress.org/advanced-administration/security/hardening/';
	private readonly Closure $readKind;

	public function __construct( ?callable $readKind = null ) {
		$this->readKind = Closure::fromCallable( $readKind ?? array( self::class, 'wordpressKind' ) );
	}

	public function id(): string {
		return 'root-exposure';
	}

	public static function decide( string $kind ): string {
		return match ( $kind ) {
			'env', 'git', 'both' => 'warn',
			'absent' => 'pass',
			default => 'unknown',
		};
	}

	public static function wordpressKind(): string {
		if ( ! defined( 'ABSPATH' ) ) {
			return 'unknown';
		}
		$env = self::entry( ABSPATH . '.env', true );
		$git = self::entry( ABSPATH . '.git', false );
		if ( 'unknown' === $env || 'unknown' === $git ) {
			return 'unknown';
		}
		if ( 'present' === $env && 'present' === $git ) {
			return 'both';
		}
		if ( 'present' === $env ) {
			return 'env';
		}
		return 'present' === $git ? 'git' : 'absent';
	}

	private static function entry( string $path, bool $file ): string {
		if ( is_link( $path ) ) {
			return 'unknown';
		}
		if ( $file ? is_file( $path ) : is_dir( $path ) ) {
			return 'present';
		}
		return file_exists( $path ) ? 'unknown' : 'absent';
	}

	public function run( ScanContext $context ): array {
		unset( $context );
		$kind    = (string) ( $this->readKind )();
		$state   = self::decide( $kind );
		$summary = match ( $kind ) {
			'env' => 'A .env file is in the site root. This check does not read or delete it.',
			'git' => 'A .git directory is in the site root. This check does not read or delete it.',
			'both' => 'A .env file and a .git directory are in the site root. This check does not read or delete them.',
			'absent' => 'No .env file or .git directory is in the site root. This check does not read or delete them.',
			default => 'The site root could not be checked for a .env file or a .git directory. This check does not read or delete them.',
		};
		return array(
			new CheckResult( $this->id(), 'warn' === $state ? State::WARN : ( 'pass' === $state ? State::PASS : State::UNKNOWN ), $summary, self::SOURCE, new DateTimeImmutable( 'now', new DateTimeZone( 'UTC' ) ), 'medium', 'unknown' === $state ? 'unavailable' : 'complete', array( 'kind' => $kind ) ),
		);
	}
}
