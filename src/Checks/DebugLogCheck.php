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

/** Reports the default content-directory debug log. It does not read or delete that file. */
final class DebugLogCheck implements SecurityCheck {
	private const SOURCE = 'https://developer.wordpress.org/advanced-administration/debug/debug-wordpress/';
	private readonly Closure $readKind;

	public function __construct( ?callable $readKind = null ) {
		$this->readKind = Closure::fromCallable( $readKind ?? array( self::class, 'wordpressKind' ) );
	}

	public function id(): string {
		return 'debug-log';
	}

	public static function decide( string $kind ): string {
		return match ( $kind ) {
			'present' => 'warn',
			'absent' => 'pass',
			default => 'unknown',
		};
	}

	public static function wordpressKind(): string {
		if ( ! defined( 'WP_CONTENT_DIR' ) ) {
			return 'unknown';
		}
		$path = WP_CONTENT_DIR . '/debug.log';
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
			'warn' => 'A debug.log file is in the content directory. This check does not read or delete it. A custom log path is not checked.',
			'pass' => 'No debug.log file is in the content directory. This check does not read or delete it. A custom log path is not checked.',
			default => 'The content directory debug log could not be checked. This check does not read or delete it.',
		};
		return array(
			new CheckResult( $this->id(), 'warn' === $state ? State::WARN : ( 'pass' === $state ? State::PASS : State::UNKNOWN ), $summary, self::SOURCE, new DateTimeImmutable( 'now', new DateTimeZone( 'UTC' ) ), 'low', 'unknown' === $state ? 'unavailable' : 'complete', array( 'kind' => $kind ) ),
		);
	}
}
