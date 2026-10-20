<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Mcp;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Admin\SiteRiskCard;
use AmazingPlugins\Security\FileScan\FileScanReport;
use AmazingPlugins\Security\FileScan\WordPressFileScanStore;
use AmazingPlugins\Security\Findings\CheckResult;
use AmazingPlugins\Security\Findings\FindingsRepository;
use AmazingPlugins\Security\Findings\SiteRisk;
use AmazingPlugins\Security\Integrity\WordPressIntegrityStore;
use AmazingPlugins\Security\Integrity\WordPressOptions;
use AmazingPlugins\Security\Scan\ScanRun;
use AmazingPlugins\Security\Vulnerabilities\VulnerabilityPreferences;
use AmazingPlugins\Security\Vulnerabilities\VulnerabilityReport;
use AmazingPlugins\Security\Vulnerabilities\WordPressVulnerabilityReportStore;
use Closure;

final class FindingsGateway {
	private readonly Closure $hardening;
	private readonly Closure $integrity;
	private readonly Closure $files;
	private readonly Closure $vulnerabilities;
	private readonly Closure $fileHistory;
	private readonly Closure $botModes;

	public function __construct( private readonly OutputProjector $projector = new OutputProjector(), ?callable $hardening = null, ?callable $integrity = null, ?callable $files = null, ?callable $vulnerabilities = null, ?callable $fileHistory = null, ?callable $botModes = null ) {
		$this->botModes        = Closure::fromCallable( $botModes ?? array( SiteRiskCard::class, 'botModes' ) );
		$this->hardening       = Closure::fromCallable( $hardening ?? static fn(): ?ScanRun => ( new FindingsRepository() )->latest() );
		$this->integrity       = Closure::fromCallable( $integrity ?? static fn(): ?ScanRun => ( new WordPressIntegrityStore( new WordPressOptions() ) )->latestCompleted() );
		$this->files           = Closure::fromCallable( $files ?? static fn(): ?FileScanReport => ( new WordPressFileScanStore( new WordPressOptions() ) )->latestCompleted() );
		$this->fileHistory     = Closure::fromCallable( $fileHistory ?? static fn(): array => ( new WordPressFileScanStore( new WordPressOptions() ) )->historicalWarnings() );
		$this->vulnerabilities = Closure::fromCallable(
			$vulnerabilities ?? static function (): ?VulnerabilityReport {
				$options = new WordPressOptions();
				if ( ! ( new VulnerabilityPreferences( $options ) )->enabled() ) {
					return null;
				}
				return ( new WordPressVulnerabilityReportStore( $options ) )->current();
			}
		);
	}

	public function list( int $offset = 0, int $limit = 50 ): array {
		$offset                            = max( 0, min( 1000, $offset ) );
		$limit                             = max( 1, min( 100, $limit ) );
		list( $findings, $sources, $risk ) = $this->snapshot();
		$complete                          = ! in_array( 'partial', $sources, true ) && ! in_array( 'unavailable', $sources, true );
		return array(
			'schema_version' => 1,
			'state'          => $complete ? 'complete' : 'inconclusive',
			'sources'        => $sources,
			'site_risk'      => $risk,
			'findings'       => array_slice( $findings, $offset, $limit ),
			'has_more'       => count( $findings ) > $offset + $limit,
			'next_offset'    => count( $findings ) > $offset + $limit ? $offset + $limit : null,
		);
	}

	public function get( string $id ): ?array {
		if ( ! preg_match( '/^[a-f0-9]{32}$/D', $id ) ) {
			return null;
		}
		foreach ( $this->snapshot()[0] as $finding ) {
			if ( hash_equals( $finding['id'], $id ) ) {
				return $finding;
			}
		}
		return null;
	}

	private function snapshot(): array {
		$out             = array();
		$hardening       = ( $this->hardening )();
		$integrity       = ( $this->integrity )();
		$files           = ( $this->files )();
		$vulnerabilities = ( $this->vulnerabilities )();
		$sources         = array(
			'hardening'     => $hardening instanceof ScanRun ? ( $hardening->partial ? 'partial' : 'complete' ) : 'unavailable',
			'integrity'     => $integrity instanceof ScanRun ? ( $integrity->partial ? 'partial' : 'complete' ) : 'unavailable',
			'file'          => $files instanceof FileScanReport ? ( $files->partial ? 'partial' : 'complete' ) : 'unavailable',
			'vulnerability' => $vulnerabilities instanceof VulnerabilityReport ? ( $vulnerabilities->partial ? 'partial' : 'complete' ) : 'unavailable',
		);
		$groups          = array(
			'hardening'     => $hardening?->results ?? array(),
			'integrity'     => $integrity?->results ?? array(),
			'vulnerability' => $vulnerabilities instanceof VulnerabilityReport ? $vulnerabilities->results : ( is_array( $vulnerabilities ) ? $vulnerabilities : array() ),
		);
		foreach ( $groups as $module => $results ) {
			foreach ( array_slice( $results, 0, 250 ) as $result ) {
				if ( $result instanceof CheckResult ) {
					$out[] = $this->projector->check( $module, $result );
				}
			}
		}
		$seen = array();
		foreach ( array_slice( $files?->findings ?? array(), 0, 250 ) as $result ) {
			$projected = is_array( $result ) ? $this->projector->file( $result, $files->partial ) : null;
			if ( null !== $projected ) {
				$out[]                    = $projected;
				$seen[ $projected['id'] ] = true;
			}
		}
		if ( null === $files || $files->partial ) {
			$kept = 0;
			foreach ( array_reverse( ( $this->fileHistory )() ) as $historical ) {
				if ( ! $historical instanceof FileScanReport || $historical->scanId === $files?->scanId ) {
					continue;
				}
				foreach ( $historical->findings as $result ) {
					if ( ! is_array( $result ) || 'warn' !== ( $result['state'] ?? null ) ) {
						continue;
					}
					$projected = $this->projector->file( $result, true, true );
					if ( null !== $projected && ! isset( $seen[ $projected['id'] ] ) ) {
						$out[]                    = $projected;
						$seen[ $projected['id'] ] = true;
						++$kept;
					}
					if ( $kept >= 250 ) {
						break 2;
					}
				}
			}
		}
		$risk = array();
		if ( $hardening instanceof ScanRun ) {
			foreach ( SiteRisk::rows( $hardening->results, array() === $groups['vulnerability'] ? null : $groups['vulnerability'], ( $this->botModes )(), time() - $hardening->finishedAt->getTimestamp() ) as $row ) {
				$risk[] = $row + array( 'summary' => SiteRiskCard::reason( $row['area'], $row['reason'] ) );
			}
		}
		return array( $out, $sources, $risk );
	}
}
