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

/** Reports a root backup of wp-config.php. It does not read or delete that file. */
final class ConfigBackupCheck implements SecurityCheck {
	private const SOURCE = 'https://developer.wordpress.org/advanced-administration/security/hardening/';
	private const NAMES  = array( 'wp-config.php.bak', 'wp-config.php.old', 'wp-config.php.orig', 'wp-config.php.save', 'wp-config.php.backup', 'wp-config.php~' );
	private readonly Closure $readKind;

	public function __construct( ?callable $readKind = null ) {
		$this->readKind = Closure::fromCallable( $readKind ?? array( self::class, 'wordpressKind' ) );
	}

	public function id(): string {
		return 'config-backup';
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
		$sawFile = false;
		foreach ( self::NAMES as $name ) {
			$path = ABSPATH . $name;
			if ( is_link( $path ) ) {
				return 'unknown';
			}
			if ( is_file( $path ) ) {
				$sawFile = true;
				continue;
			}
			if ( file_exists( $path ) ) {
				return 'unknown';
			}
		}
		return $sawFile ? 'present' : 'absent';
	}

	public function run( ScanContext $context ): array {
		unset( $context );
		$kind    = (string) ( $this->readKind )();
		$state   = self::decide( $kind );
		$summary = match ( $state ) {
			'warn' => __( 'A backup copy of wp-config.php is in the site root. This check does not read or delete it.', 'amazingplugins-security-scanner' ),
			'pass' => __( 'No backup copy of wp-config.php is in the site root. This check does not read or delete it.', 'amazingplugins-security-scanner' ),
			default => __( 'A backup copy of wp-config.php could not be checked. This check does not read or delete it.', 'amazingplugins-security-scanner' ),
		};
		return array(
			new CheckResult( $this->id(), 'warn' === $state ? State::WARN : ( 'pass' === $state ? State::PASS : State::UNKNOWN ), $summary, self::SOURCE, new DateTimeImmutable( 'now', new DateTimeZone( 'UTC' ) ), 'low', 'unknown' === $state ? 'unavailable' : 'complete', array( 'kind' => $kind ) ),
		);
	}
}
