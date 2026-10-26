<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Checks;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Findings\CheckResult;
use AmazingPlugins\Security\Findings\State;
use AmazingPlugins\Security\Scan\ScanContext;
use AmazingPlugins\Security\Scan\SecurityCheck;
use Closure;
use DateTimeImmutable;
use DateTimeZone;

/** Reports a root wp-config-sample.php file. It does not delete that file. */
final class SampleConfigCheck implements SecurityCheck {
	private const SOURCE = 'https://developer.wordpress.org/advanced-administration/security/hardening/';
	private readonly Closure $readKind;

	public function __construct( ?callable $readKind = null ) {
		$this->readKind = Closure::fromCallable( $readKind ?? array( self::class, 'wordpressKind' ) );
	}

	public function id(): string {
		return 'sample-config';
	}

	public static function decide( string $kind ): string {
		return match ( $kind ) {
			'present' => 'warn',
			'absent' => 'pass',
			default => 'unknown',
		};
	}

	public static function wordpressKind(): string {
		if ( ! defined( 'ABSPATH' ) ) {
			return 'unknown';
		}
		$path = ABSPATH . 'wp-config-sample.php';
		if ( is_link( $path ) ) {
			return 'unknown';
		}
		if ( is_file( $path ) ) {
			return 'present';
		}
		return file_exists( $path ) ? 'unknown' : 'absent';
	}

	public function run( ScanContext $context ): array {
		unset( $context );
		$kind    = (string) ( $this->readKind )();
		$state   = self::decide( $kind );
		$summary = match ( $state ) {
			'warn' => __( 'A wp-config-sample.php file is in the site root. This check does not delete it.', 'amazing-security-scanner' ),
			'pass' => __( 'No wp-config-sample.php file is in the site root. This check does not delete it.', 'amazing-security-scanner' ),
			default => __( 'The sample config file could not be checked. This check does not delete it.', 'amazing-security-scanner' ),
		};
		return array(
			new CheckResult( $this->id(), 'warn' === $state ? State::WARN : ( 'pass' === $state ? State::PASS : State::UNKNOWN ), $summary, self::SOURCE, new DateTimeImmutable( 'now', new DateTimeZone( 'UTC' ) ), 'low', 'unknown' === $state ? 'unavailable' : 'complete', array( 'kind' => $kind ) ),
		);
	}
}
