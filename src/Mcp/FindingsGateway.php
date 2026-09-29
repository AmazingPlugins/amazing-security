<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Mcp;

use AmazingPlugins\Security\FileScan\FileScanReport;
use AmazingPlugins\Security\FileScan\WordPressFileScanStore;
use AmazingPlugins\Security\Findings\CheckResult;
use AmazingPlugins\Security\Findings\FindingsRepository;
use AmazingPlugins\Security\Integrity\WordPressIntegrityStore;
use AmazingPlugins\Security\Integrity\WordPressOptions;
use AmazingPlugins\Security\Scan\ScanRun;
use AmazingPlugins\Security\Vulnerabilities\VulnerabilityPreferences;
use AmazingPlugins\Security\Vulnerabilities\WordPressVulnerabilityReportStore;
use Closure;

final class FindingsGateway {
	private readonly Closure $hardening;
	private readonly Closure $integrity;
	private readonly Closure $files;
	private readonly Closure $vulnerabilities;

	public function __construct( private readonly OutputProjector $projector = new OutputProjector(), ?callable $hardening = null, ?callable $integrity = null, ?callable $files = null, ?callable $vulnerabilities = null ) {
		$this->hardening       = Closure::fromCallable( $hardening ?? static fn(): ?ScanRun => ( new FindingsRepository() )->latest() );
		$this->integrity       = Closure::fromCallable( $integrity ?? static fn(): ?ScanRun => ( new WordPressIntegrityStore( new WordPressOptions() ) )->latestCompleted() );
		$this->files           = Closure::fromCallable( $files ?? static fn(): ?FileScanReport => ( new WordPressFileScanStore( new WordPressOptions() ) )->latestCompleted() );
		$this->vulnerabilities = Closure::fromCallable(
			$vulnerabilities ?? static function (): ?array {
				$options = new WordPressOptions();
				if ( ! ( new VulnerabilityPreferences( $options ) )->enabled() ) {
					return null;
				}
				return ( new WordPressVulnerabilityReportStore( $options ) )->current()?->results;
			}
		);
	}

	public function list( int $offset = 0, int $limit = 50 ): array {
		$offset   = max( 0, min( 1000, $offset ) );
		$limit    = max( 1, min( 100, $limit ) );
		$findings = $this->all();
		return array(
			'schema_version' => 1,
			'findings'       => array_slice( $findings, $offset, $limit ),
			'has_more'       => count( $findings ) > $offset + $limit,
			'next_offset'    => count( $findings ) > $offset + $limit ? $offset + $limit : null,
		);
	}

	public function get( string $id ): ?array {
		if ( ! preg_match( '/^[a-f0-9]{32}$/D', $id ) ) {
			return null;
		}
		foreach ( $this->all() as $finding ) {
			if ( hash_equals( $finding['id'], $id ) ) {
				return $finding;
			}
		}
		return null;
	}

	private function all(): array {
		$out = array();
		foreach ( array(
			'hardening'     => ( $this->hardening )()?->results ?? array(),
			'integrity'     => ( $this->integrity )()?->results ?? array(),
			'vulnerability' => ( $this->vulnerabilities )() ?? array(),
		) as $module => $results ) {
			foreach ( array_slice( $results, 0, 250 ) as $result ) {
				if ( $result instanceof CheckResult ) {
					$out[] = $this->projector->check( $module, $result );
				}
			}
		}
		$files = ( $this->files )();
		foreach ( array_slice( $files?->findings ?? array(), 0, 250 ) as $result ) {
			$projected = is_array( $result ) ? $this->projector->file( $result ) : null;
			if ( null !== $projected ) {
				$out[] = $projected;
			}
		}
		return $out;
	}
}
