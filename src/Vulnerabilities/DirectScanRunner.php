<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Vulnerabilities;

defined( 'ABSPATH' ) || exit;

final class DirectScanRunner {
	/** @param null|callable(InstalledSoftware):?string $provenance
	 *  @param null|callable(InstalledSoftware,string):bool $stateStillMatches
	 */
	public function __construct( private readonly DirectFeedClient $client, private readonly DirectVulnerabilityMatcher $matcher = new DirectVulnerabilityMatcher(), private readonly mixed $provenance = null, private readonly mixed $stateStillMatches = null, private readonly mixed $shouldContinue = null ) {}

	/** @param InstalledSoftware[] $inventory */
	public function step( array $inventory, int $offset, int $now, string $phase = 'feed', array $verified = array() ): DirectScanStep {
		$total = min( 250, count( $inventory ) );
		if ( 'provenance' === $phase && is_callable( $this->provenance ) ) {
			$next   = max( 0, $offset );
			$proved = 0;
			while ( $next < $total && $next < $offset + 10 ) {
				if ( ! $this->canContinue() ) {
					return new DirectScanStep( $next, null, false, 'provenance', $verified );
				}
				$item = $inventory[ $next ];
				if ( 'plugin' === $item->type ) {
					if ( $proved >= 1 ) {
						break;
					}
					$key   = $item->type . ':' . $item->slug . ':' . $item->version;
					$proof = ( $this->provenance )( $item );
					if ( is_string( $proof ) && '' !== $proof ) {
						$verified[ $key ] = $proof;
					}
					++$proved;
				}
				++$next;
			}
			if ( $next < $total ) {
				return new DirectScanStep( $next, null, false, 'provenance', $verified );
			}
		} else {
			$next = min( $total, max( 0, $offset ) + 3 );
			for ( $i = max( 0, $offset ); $i < $next; ++$i ) {
				if ( ! $this->canContinue() ) {
					return new DirectScanStep( $i, null, false, 'feed', $verified );
				}
				$item = $inventory[ $i ];
				$key  = 'core' === $item->type ? $item->version : $item->slug;
				$this->client->lookup( $item->type, $key, $now );
			}
			if ( $next < $total ) {
				return new DirectScanStep( $next, null );
			}
			if ( is_callable( $this->provenance ) ) {
				return new DirectScanStep( 0, null, false, 'provenance', $verified );
			}
		}
		$responses          = array();
		$allFetched         = true;
		$matchedInventory   = array();
		$validationDeadline = microtime( true ) + 5.0;
		foreach ( array_slice( $inventory, 0, $total ) as $item ) {
			if ( ! $this->canContinue() ) {
				return new DirectScanStep( 0, null, false, 'feed', $verified );
			}
			$key                                   = 'core' === $item->type ? $item->version : $item->slug;
			$responses[ $item->type . ':' . $key ] = $this->client->cached( $item->type, $key, $now );
			$allFetched                            = $allFetched && null !== $responses[ $item->type . ':' . $key ];
			$identity                              = $item->type . ':' . $item->slug . ':' . $item->version;
			$proof                                 = $verified[ $identity ] ?? null;
			$eligible                              = 'plugin' === $item->type && is_string( $proof ) && is_callable( $this->stateStillMatches ) && microtime( true ) < $validationDeadline && ( $this->stateStillMatches )( $item, $proof );
			$proofAt                               = $eligible && preg_match( '/^([0-9]{10}):/', $proof, $matches ) ? (int) $matches[1] : null;
			$matchedInventory[]                    = new InstalledSoftware( $item->type, $item->slug, $item->version, $eligible, $proofAt );
		}
		$report = $this->matcher->evaluate( $matchedInventory, $responses, $now );
		if ( count( $inventory ) > $total ) {
			$report = new VulnerabilityReport( $report->results, true, 'Inventory exceeded direct-check limit.', $report->snapshotGeneratedAt, null );
		}
		return new DirectScanStep( $total, $report, $allFetched && count( $inventory ) <= $total, 'complete', $verified );
	}

	private function canContinue(): bool {
		return ! is_callable( $this->shouldContinue ) || ( $this->shouldContinue )();
	}
}
