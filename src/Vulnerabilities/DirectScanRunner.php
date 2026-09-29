<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Vulnerabilities;

final class DirectScanRunner {
	/** @param null|callable(InstalledSoftware):bool $provenance */
	public function __construct( private readonly DirectFeedClient $client, private readonly DirectVulnerabilityMatcher $matcher = new DirectVulnerabilityMatcher(), private readonly mixed $provenance = null ) {}

	/** @param InstalledSoftware[] $inventory */
	public function step( array $inventory, int $offset, int $now, string $phase = 'feed', array $verified = array() ): DirectScanStep {
		$total = min( 250, count( $inventory ) );
		if ( 'provenance' === $phase && is_callable( $this->provenance ) ) {
			$next   = max( 0, $offset );
			$proved = 0;
			while ( $next < $total && $next < $offset + 10 ) {
				$item = $inventory[ $next ];
				if ( 'plugin' === $item->type ) {
					if ( $proved >= 1 ) {
						break;
					}
					$key              = $item->type . ':' . $item->slug . ':' . $item->version;
					$verified[ $key ] = (bool) ( $this->provenance )( $item );
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
		$responses        = array();
		$allFetched       = true;
		$matchedInventory = array();
		foreach ( array_slice( $inventory, 0, $total ) as $item ) {
			$key                                   = 'core' === $item->type ? $item->version : $item->slug;
			$responses[ $item->type . ':' . $key ] = $this->client->cached( $item->type, $key, $now );
			$allFetched                            = $allFetched && null !== $responses[ $item->type . ':' . $key ];
			$identity                              = $item->type . ':' . $item->slug . ':' . $item->version;
			$matchedInventory[]                    = new InstalledSoftware( $item->type, $item->slug, $item->version, $item->eligible || true === ( $verified[ $identity ] ?? false ) );
		}
		$report = $this->matcher->evaluate( $matchedInventory, $responses );
		if ( count( $inventory ) > $total ) {
			$report = new VulnerabilityReport( $report->results, true, 'Inventory exceeded direct-check limit.', $report->snapshotGeneratedAt, null );
		}
		return new DirectScanStep( $total, $report, $allFetched && count( $inventory ) <= $total, 'complete', $verified );
	}
}
