<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Checks;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Content\ContentCursor;
use AmazingPlugins\Security\FileScan\FileScanReport;
use AmazingPlugins\Security\Findings\CheckResult;
use AmazingPlugins\Security\Findings\State;
use AmazingPlugins\Security\Scan\ScanContext;
use AmazingPlugins\Security\Scan\ScanRun;
use AmazingPlugins\Security\Scan\SecurityCheck;
use Closure;
use DateTimeImmutable;
use DateTimeZone;
use Throwable;

/** Reads a stored scan and suggests the next look. It does not start one. */
final class FollowUpCheck implements SecurityCheck {
	private const SOURCE = 'https://developer.wordpress.org/advanced-administration/security/hardening/';
	private const COPY   = array(
		'release-files'    => array(
			'none'    => 'Release files have not been compared with WordPress.org. Start the integrity scan on this page.',
			'found'   => 'A release file does not match WordPress.org. Review the integrity section on this page.',
			'clean'   => 'The last integrity scan did not record a release-file difference.',
			'partial' => 'The last integrity scan did not finish. Continue it on this page.',
			'unknown' => 'The stored integrity result could not be read.',
		),
		'closed-plugins'   => array(
			'none'    => 'Closed plugins have not been checked. Review directory status on this page.',
			'found'   => 'An installed plugin is closed on WordPress.org. Review the directory section on this page.',
			'clean'   => 'The stored directory check did not find a closed plugin.',
			'partial' => 'A directory record could not be confirmed. Review the directory section on this page.',
			'unknown' => 'The stored directory result could not be read.',
		),
		'public-content'   => array(
			'none'    => 'Posts and comments have not been checked for suspicious links. Start the content scan on this page.',
			'found'   => 'A post or comment matched a suspicious-content rule. Review the content section on this page.',
			'clean'   => 'The last content scan did not record a suspicious link.',
			'partial' => 'The last content scan did not finish. Continue it on this page.',
			'unknown' => 'The stored content result could not be read.',
		),
		'suspicious-files' => array(
			'none'    => 'Suspicious code in plugin and theme files has not been checked. Run the file scan on this page.',
			'found'   => 'A file matched a suspicious-code rule. Review the suspicious files section on this page.',
			'clean'   => 'The last file scan did not record a suspicious-code match.',
			'partial' => 'The last file scan did not finish. Continue it on this page.',
			'unknown' => 'The stored file scan could not be read.',
		),
		'local-inventory'  => array(
			'none'    => 'Public file names have not been inventoried. Review the local inventory on this page.',
			'found'   => 'The local inventory lists a selected public file name. Review the local inventory on this page.',
			'clean'   => 'The stored inventory did not list a selected public file name.',
			'partial' => 'The local inventory did not finish every location. Review it on this page.',
			'unknown' => 'The stored inventory could not be read.',
		),
		'security-headers' => array(
			'none'    => 'Response headers have not been checked. Review security headers on this page.',
			'found'   => 'A selected response header was missing on the last check. Review security headers on this page.',
			'clean'   => 'The last header check did not record a missing selected header.',
			'partial' => 'The last header check could not assess the homepage. Review security headers on this page.',
			'unknown' => 'The stored header check could not be read.',
		),
	);
	private readonly Closure $read;

	public function __construct( private readonly string $checkId, callable $read ) {
		$this->read = Closure::fromCallable( $read );
	}

	public function id(): string {
		return $this->checkId;
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
		$stored = is_string( $snapshot['stored'] ?? null ) && isset( self::COPY[ $this->checkId ][ $snapshot['stored'] ] ) ? $snapshot['stored'] : 'unknown';
		$found  = is_int( $snapshot['found'] ?? null ) && $snapshot['found'] >= 0 && $snapshot['found'] <= 250 ? $snapshot['found'] : 0;
		$state  = match ( $stored ) {
			'none', 'found' => State::WARN,
			'clean' => State::PASS,
			default => State::UNKNOWN,
		};
		$line = self::COPY[ $this->checkId ][ $stored ] ?? __( 'The stored result could not be read.', 'amsec-security-scanner' );
		return array(
			new CheckResult(
				$this->id(),
				$state,
				$line . ' This check does not start a new scan.',
				self::SOURCE,
				new DateTimeImmutable( 'now', new DateTimeZone( 'UTC' ) ),
				State::UNKNOWN === $state ? 'low' : 'medium',
				State::UNKNOWN === $state ? 'unavailable' : 'complete',
				array(
					'stored'      => $stored,
					'found_count' => $found,
				)
			),
		);
	}

	/** @return array{stored: string, found: int} */
	public static function releaseFiles(): array {
		return self::integritySnapshot( 'amsec_security_scanner_integrity_completed', 'amsec_security_scanner_integrity_active' );
	}

	/** @return array{stored: string, found: int} */
	public static function closedPlugins(): array {
		$raw = get_option( 'amsec_repository_state', null );
		if ( ! is_string( $raw ) || '' === $raw ) {
			return array(
				'stored' => 'none',
				'found'  => 0,
			);
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.json_decode_json_decode -- Local directory record only. No directory request is made.
		$state = json_decode( $raw, true );
		if ( ! is_array( $state ) || 1 !== ( $state['version'] ?? null ) || ! is_array( $state['records'] ?? null ) ) {
			return array(
				'stored' => 'unknown',
				'found'  => 0,
			);
		}
		if ( array() === $state['records'] ) {
			return array(
				'stored' => 'none',
				'found'  => 0,
			);
		}
		$closed = 0;
		$unsure = 0;
		foreach ( $state['records'] as $row ) {
			$status = is_array( $row ) && is_array( $row['result'] ?? null ) ? ( $row['result']['state'] ?? '' ) : '';
			if ( 'closed' === $status ) {
				++$closed;
			} elseif ( 'unknown' === $status ) {
				++$unsure;
			} elseif ( 'listed' !== $status ) {
				return array(
					'stored' => 'unknown',
					'found'  => 0,
				);
			}
		}
		if ( $closed > 0 ) {
			return array(
				'stored' => 'found',
				'found'  => $closed,
			);
		}
		return array(
			'stored' => $unsure > 0 ? 'partial' : 'clean',
			'found'  => 0,
		);
	}

	/** @return array{stored: string, found: int} */
	public static function suspiciousFiles(): array {
		return self::fileScanSnapshot( 'amsec_security_scanner_file_scan_completed', 'amsec_security_scanner_file_scan_active' );
	}

	/** @return array{stored: string, found: int} */
	public static function localInventory(): array {
		$raw = get_option( 'amsec_exposure_state', null );
		if ( ! is_string( $raw ) || '' === $raw ) {
			return array(
				'stored' => 'none',
				'found'  => 0,
			);
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.json_decode_json_decode -- Local inventory record only. No new inventory is started.
		$state = json_decode( $raw, true );
		if ( ! is_array( $state ) || 1 !== ( $state['version'] ?? null ) || ! is_array( $state['reports'] ?? null ) ) {
			return array(
				'stored' => 'unknown',
				'found'  => 0,
			);
		}
		if ( array() === $state['reports'] ) {
			return array(
				'stored' => 'none',
				'found'  => 0,
			);
		}
		$seen    = 0;
		$found   = 0;
		$partial = false;
		foreach ( $state['reports'] as $alias => $report ) {
			if ( ! in_array( $alias, array( 'site', 'content', 'uploads' ), true ) || ! is_array( $report ) || ! is_array( $report['candidates'] ?? null ) ) {
				return array(
					'stored' => 'unknown',
					'found'  => 0,
				);
			}
			++$seen;
			$partial = $partial || ! empty( $report['partial'] );
			$found  += count( $report['candidates'] );
		}
		if ( $found > 0 ) {
			return array(
				'stored' => 'found',
				'found'  => min( 250, $found ),
			);
		}
		return array(
			'stored' => $partial || $seen < 3 ? 'partial' : 'clean',
			'found'  => 0,
		);
	}

	/** @return array{stored: string, found: int} */
	public static function securityHeaders(): array {
		$raw = get_option( 'amsec_headers_state', null );
		if ( ! is_string( $raw ) || '' === $raw ) {
			return array(
				'stored' => 'none',
				'found'  => 0,
			);
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.json_decode_json_decode -- Local header record only. No homepage request is made.
		$state = json_decode( $raw, true );
		if ( ! is_array( $state ) || 1 !== ( $state['version'] ?? null ) || ! array_key_exists( 'latest', $state ) ) {
			return array(
				'stored' => 'unknown',
				'found'  => 0,
			);
		}
		if ( null === $state['latest'] ) {
			return array(
				'stored' => 'none',
				'found'  => 0,
			);
		}
		$result = is_array( $state['latest'] ) ? ( $state['latest']['result'] ?? null ) : null;
		if ( ! is_array( $result ) ) {
			return array(
				'stored' => 'unknown',
				'found'  => 0,
			);
		}
		if ( 'unknown' === ( $result['state'] ?? '' ) ) {
			return array(
				'stored' => 'partial',
				'found'  => 0,
			);
		}
		$headers = $result['headers'] ?? null;
		if ( 'assessed' !== ( $result['state'] ?? '' ) || ! is_array( $headers ) ) {
			return array(
				'stored' => 'unknown',
				'found'  => 0,
			);
		}
		$missing = 0;
		foreach ( array( 'hsts', 'content_type', 'framing', 'referrer', 'csp' ) as $name ) {
			if ( 'missing' === ( $headers[ $name ] ?? '' ) ) {
				++$missing;
			}
		}
		return array(
			'stored' => $missing > 0 ? 'found' : 'clean',
			'found'  => min( 250, $missing ),
		);
	}

	/** @return array{stored: string, found: int} */
	public static function publicContent(): array {
		$raw = get_option( 'amsec_content_state', null );
		if ( ! is_string( $raw ) || '' === $raw ) {
			return array(
				'stored' => 'none',
				'found'  => 0,
			);
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.json_decode_json_decode -- Local content-scan record only. No new scan is started.
		$state = json_decode( $raw, true );
		if ( ! is_array( $state ) || 1 !== ( $state['version'] ?? null ) || ! array_key_exists( 'complete', $state ) ) {
			return array(
				'stored' => 'unknown',
				'found'  => 0,
			);
		}
		$complete = $state['complete'];
		if ( null === $complete ) {
			return array(
				'stored' => is_array( $state['active'] ?? null ) ? 'partial' : 'none',
				'found'  => 0,
			);
		}
		$cursor = is_array( $complete ) ? ContentCursor::fromArray( $complete ) : null;
		if ( ! $cursor instanceof ContentCursor ) {
			return array(
				'stored' => 'unknown',
				'found'  => 0,
			);
		}
		$found = count( $cursor->findings );
		if ( $found > 0 ) {
			return array(
				'stored' => 'found',
				'found'  => $found,
			);
		}
		return array(
			'stored' => $cursor->partial || ! $cursor->finished ? 'partial' : 'clean',
			'found'  => 0,
		);
	}

	/** @return array{stored: string, found: int} */
	private static function integritySnapshot( string $completedKey, string $activeKey ): array {
		$raw = get_option( $completedKey, null );
		if ( ! is_string( $raw ) || '' === $raw ) {
			$active = get_option( $activeKey, null );
			return array(
				'stored' => is_string( $active ) && '' !== $active ? 'partial' : 'none',
				'found'  => 0,
			);
		}
		try {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.json_decode_json_decode -- Local integrity report only. No release download is started.
			$data = json_decode( $raw, true );
			$run  = is_array( $data ) ? ScanRun::fromArray( $data ) : null;
		} catch ( Throwable ) {
			$run = null;
		}
		if ( ! $run instanceof ScanRun ) {
			return array(
				'stored' => 'unknown',
				'found'  => 0,
			);
		}
		$found = 0;
		foreach ( $run->results as $result ) {
			if ( in_array( $result->state, array( State::WARN, State::CRITICAL, State::FAIL ), true ) ) {
				++$found;
			}
		}
		if ( $found > 0 ) {
			return array(
				'stored' => 'found',
				'found'  => min( 250, $found ),
			);
		}
		return array(
			'stored' => $run->partial ? 'partial' : 'clean',
			'found'  => 0,
		);
	}

	/** @return array{stored: string, found: int} */
	private static function fileScanSnapshot( string $completedKey, string $activeKey ): array {
		$raw = get_option( $completedKey, null );
		if ( ! is_string( $raw ) || '' === $raw ) {
			$active = get_option( $activeKey, null );
			return array(
				'stored' => is_string( $active ) && '' !== $active ? 'partial' : 'none',
				'found'  => 0,
			);
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.json_decode_json_decode -- Local file-scan report only. No new scan is started.
		$data   = json_decode( $raw, true );
		$report = is_array( $data ) ? FileScanReport::fromArray( $data ) : null;
		if ( ! $report instanceof FileScanReport ) {
			return array(
				'stored' => 'unknown',
				'found'  => 0,
			);
		}
		$found = count( $report->findings );
		if ( $found > 250 ) {
			$found = 250;
		}
		if ( $found > 0 || 'warn' === $report->state ) {
			return array(
				'stored' => 'found',
				'found'  => $found,
			);
		}
		return array(
			'stored' => $report->partial || 'inconclusive' === $report->state ? 'partial' : 'clean',
			'found'  => 0,
		);
	}
}
