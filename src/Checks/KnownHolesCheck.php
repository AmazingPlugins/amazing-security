<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Checks;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Findings\CheckResult;
use AmazingPlugins\Security\Findings\State;
use AmazingPlugins\Security\Scan\ScanContext;
use AmazingPlugins\Security\Scan\SecurityCheck;
use AmazingPlugins\Security\Vulnerabilities\VulnerabilityReport;
use Closure;
use DateTimeImmutable;
use DateTimeZone;
use Throwable;

/** Points at the stored vulnerability result. It does not contact a provider. */
final class KnownHolesCheck implements SecurityCheck {
	private const SOURCE = 'https://www.wpvulnerability.com/';
	private readonly Closure $read;

	public function __construct( callable $read ) {
		$this->read = Closure::fromCallable( $read );
	}

	public function id(): string {
		return 'known-holes';
	}

	public function run( ScanContext $context ): array {
		try {
			$snapshot = ( $this->read )();
		} catch ( Throwable ) {
			$snapshot = array();
		}
		if ( ! is_array( $snapshot ) ) {
			$snapshot = array();
		}
		$enabled = is_string( $snapshot['enabled'] ?? null ) && in_array( $snapshot['enabled'], array( 'yes', 'no' ), true ) ? $snapshot['enabled'] : 'unknown';
		$stored  = is_string( $snapshot['stored'] ?? null ) && in_array( $snapshot['stored'], array( 'none', 'clean', 'found', 'partial', 'unknown' ), true ) ? $snapshot['stored'] : 'unknown';
		$found   = is_int( $snapshot['found'] ?? null ) && $snapshot['found'] >= 0 && $snapshot['found'] <= 250 ? $snapshot['found'] : 0;
		$state   = match ( true ) {
			'unknown' === $enabled => State::UNKNOWN,
			'no' === $enabled, 'found' === $stored, 'none' === $stored => State::WARN,
			'clean' === $stored => State::PASS,
			default => State::UNKNOWN,
		};
		return array(
			new CheckResult(
				$this->id(),
				$state,
				self::summary( $enabled, $stored ),
				self::SOURCE,
				new DateTimeImmutable( 'now', new DateTimeZone( 'UTC' ) ),
				State::UNKNOWN === $state ? 'low' : 'medium',
				State::UNKNOWN === $state ? 'unavailable' : 'complete',
				array(
					'enabled'     => $enabled,
					'stored'      => $stored,
					'found_count' => $found,
				)
			),
		);
	}

	/** @return array{enabled: string, stored: string, found: int} */
	public static function wordpressSnapshot(): array {
		$flag    = get_option( 'amazing_security_vulnerability_direct_enabled', null );
		$enabled = '1' === $flag ? 'yes' : ( in_array( $flag, array( '0', '', false, null ), true ) ? 'no' : 'unknown' );
		$raw     = get_option( 'amazing_security_vulnerability_current', null );
		if ( ! is_string( $raw ) || '' === $raw ) {
			return array(
				'enabled' => $enabled,
				'stored'  => 'none',
				'found'   => 0,
			);
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.json_decode_json_decode -- Local stored report only. No provider request is made.
		$data   = json_decode( $raw, true );
		$report = is_array( $data ) ? VulnerabilityReport::fromArray( $data ) : null;
		if ( ! $report instanceof VulnerabilityReport ) {
			return array(
				'enabled' => $enabled,
				'stored'  => 'unknown',
				'found'   => 0,
			);
		}
		$found = 0;
		foreach ( $report->results as $result ) {
			if ( in_array( $result->state, array( State::WARN, State::CRITICAL, State::FAIL ), true ) ) {
				++$found;
			}
		}
		$stored = $found > 0 ? 'found' : ( $report->partial ? 'partial' : 'clean' );
		return array(
			'enabled' => $enabled,
			'stored'  => $stored,
			'found'   => $found,
		);
	}

	private static function summary( string $enabled, string $stored ): string {
		$text = match ( true ) {
			'unknown' === $enabled => __( 'Vulnerability check status could not be read.', 'amazing-security' ),
			'no' === $enabled => __( 'Known holes in installed plugins and themes are not being checked. Turn on vulnerability checks on this page when you want this site to ask the provider.', 'amazing-security' ),
			'found' === $stored => __( 'A published issue matches an installed package. Review the vulnerability section on this page.', 'amazing-security' ),
			'none' === $stored => __( 'Vulnerability checks are on, and no result is stored yet. Use Check installed versions on this page.', 'amazing-security' ),
			'clean' === $stored => __( 'The last stored vulnerability check did not match a published issue to an installed package.', 'amazing-security' ),
			'partial' === $stored => __( 'The last vulnerability check did not finish every package. Continue it from this page.', 'amazing-security' ),
			default => __( 'The stored vulnerability result could not be read.', 'amazing-security' ),
		};
		return $text . ' This check does not contact the provider.';
	}
}
