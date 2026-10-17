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

/** Compares PHP with the version this WordPress release already requires. It does not contact WordPress.org. */
final class PhpVersionCheck implements SecurityCheck {
	private const SOURCE = 'https://developer.wordpress.org/advanced-administration/before-installing/howto-install/';
	private readonly Closure $readKind;

	public function __construct( ?callable $readKind = null ) {
		$this->readKind = Closure::fromCallable( $readKind ?? array( self::class, 'wordpressKind' ) );
	}

	public function id(): string {
		return 'php-version';
	}

	public static function decide( string $kind ): string {
		return match ( $kind ) {
			'older' => 'warn',
			'current' => 'pass',
			default => 'unknown',
		};
	}

	public static function wordpressKind(): string {
		global $required_php_version;
		if ( ! is_string( $required_php_version ) || 1 !== preg_match( '/^\d+\.\d+\.\d+$/', $required_php_version ) ) {
			return 'unknown';
		}
		return version_compare( PHP_VERSION, $required_php_version, '<' ) ? 'older' : 'current';
	}

	public function run( ScanContext $context ): array {
		unset( $context );
		$kind    = (string) ( $this->readKind )();
		$state   = self::decide( $kind );
		$summary = match ( $state ) {
			'warn' => __( 'PHP is older than the version this WordPress release requires. This check does not change PHP and does not contact WordPress.org.', 'amazing-security' ),
			'pass' => __( 'PHP meets the version this WordPress release requires. This check does not change PHP and does not contact WordPress.org.', 'amazing-security' ),
			default => __( 'The required PHP version could not be read. This check does not change PHP and does not contact WordPress.org.', 'amazing-security' ),
		};
		return array(
			new CheckResult( $this->id(), 'warn' === $state ? State::WARN : ( 'pass' === $state ? State::PASS : State::UNKNOWN ), $summary, self::SOURCE, new DateTimeImmutable( 'now', new DateTimeZone( 'UTC' ) ), 'low', 'unknown' === $state ? 'unavailable' : 'complete', array( 'kind' => $kind ) ),
		);
	}
}
