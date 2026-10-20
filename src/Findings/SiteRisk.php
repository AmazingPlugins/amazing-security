<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Findings;

defined( 'ABSPATH' ) || exit;

/** Sums up stored results into one Good, Check or Risk row per area. It reads nothing and runs no check. */
final class SiteRisk {
	public const GOOD  = 'good';
	public const CHECK = 'check';
	public const RISK  = 'risk';
	private const WEEK = 604800;

	/**
	 * @param array<int, mixed>         $findings Latest hardening scan results.
	 * @param array<int, mixed>|null    $packages Latest vulnerability report results, or null when checks are off or no report is stored.
	 * @param array{0: string, 1: string, 2: string} $botModes Bot control, scanner guard and rate limit modes.
	 * @param int                       $age      Seconds since the hardening scan finished.
	 * @return list<array{area: string, status: string, reason: string}>
	 */
	public static function rows( array $findings, ?array $packages, array $botModes, int $age ): array {
		$by = array();
		foreach ( $findings as $result ) {
			if ( $result instanceof CheckResult && ! isset( $by[ $result->checkId ] ) ) {
				$by[ $result->checkId ] = $result;
			}
		}
		$ev = static fn ( string $id, string $key ): string => isset( $by[ $id ] ) && is_scalar( $by[ $id ]->evidence[ $key ] ?? null ) ? (string) $by[ $id ]->evidence[ $key ] : '';
		return array(
			self::row( 'plugins', self::plugins( $packages, $ev( 'known-holes', 'enabled' ) ) ),
			self::row( 'files', self::files( $ev, $age ) ),
			self::row( 'bots', self::bots( $botModes ) ),
			self::row( 'ai', self::ai( $ev, isset( $by['https-admin'] ) ? $by['https-admin']->state : '' ) ),
			self::row( 'signin', self::signIn( $ev( 'login-rate-mode', 'mode' ) ) ),
		);
	}

	/**
	 * @param array{0: string, 1: string} $verdict
	 * @return array{area: string, status: string, reason: string}
	 */
	private static function row( string $area, array $verdict ): array {
		return array(
			'area'   => $area,
			'status' => $verdict[0],
			'reason' => $verdict[1],
		);
	}

	/** @return array{0: string, 1: string} */
	private static function plugins( ?array $packages, string $enabled ): array {
		if ( null === $packages || array() === $packages ) {
			return array( self::CHECK, 'no' === $enabled ? 'off' : 'no-report' );
		}
		$watch = false;
		$high  = false;
		foreach ( $packages as $result ) {
			$risk = $result instanceof CheckResult ? ( $result->evidence['risk'] ?? '' ) : '';
			if ( 'high' === $risk && true === ( $result->evidence['exploited'] ?? false ) ) {
				return array( self::RISK, 'exploited' );
			}
			$high  = $high || 'high' === $risk;
			$watch = $watch || 'watch' === $risk;
		}
		if ( $high ) {
			return array( self::RISK, 'open-hole' );
		}
		return $watch ? array( self::CHECK, 'watch' ) : array( self::GOOD, 'clear' );
	}

	/** @return array{0: string, 1: string} */
	private static function files( callable $ev, int $age ): array {
		if ( 'found' === $ev( 'local-code', 'stored' ) || 'found' === $ev( 'suspicious-files', 'stored' ) ) {
			return array( self::RISK, 'malware' );
		}
		if ( 'present' === $ev( 'uploads-php-files', 'kind' ) ) {
			return array( self::RISK, 'uploads-php' );
		}
		if ( 'found' === $ev( 'release-files', 'stored' ) ) {
			return array( self::RISK, 'core-changed' );
		}
		if ( 'clean' !== $ev( 'local-code', 'stored' ) ) {
			return array( self::CHECK, 'not-run' );
		}
		return $age > self::WEEK ? array( self::CHECK, 'stale' ) : array( self::GOOD, 'clear' );
	}

	/**
	 * @param array{0: string, 1: string, 2: string} $modes
	 * @return array{0: string, 1: string}
	 */
	private static function bots( array $modes ): array {
		if ( in_array( 'block', $modes, true ) ) {
			return array( self::GOOD, 'on' );
		}
		return array() === array_diff( $modes, array( 'off' ) ) ? array( self::RISK, 'all-off' ) : array( self::CHECK, 'watch-only' );
	}

	/** @return array{0: string, 1: string} */
	private static function ai( callable $ev, string $https ): array {
		$assistant = $ev( 'ai-readiness', 'assistant' );
		if ( 'on' === $assistant && State::PASS !== $https ) {
			return array( self::RISK, 'assistant-plain' );
		}
		if ( ! in_array( $assistant, array( 'on', 'off' ), true ) ) {
			return array( self::CHECK, 'unknown' );
		}
		if ( 'allowed' === $ev( 'ai-readers', 'ai_crawlers' ) ) {
			return array( self::CHECK, 'crawlers' );
		}
		if ( 'absent' === $ev( 'ai-readiness', 'guide' ) ) {
			return array( self::CHECK, 'no-guide' );
		}
		return array( self::GOOD, 'ready' );
	}

	/** @return array{0: string, 1: string} */
	private static function signIn( string $mode ): array {
		return match ( $mode ) {
			'off' => array( self::RISK, 'off' ),
			'observe' => array( self::CHECK, 'watch' ),
			'block' => array( self::GOOD, 'on' ),
			default => array( self::CHECK, 'unknown' ),
		};
	}
}
