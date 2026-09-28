<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

use AmazingPlugins\Security\Integrity\IntegrityStep;
use AmazingPlugins\Security\Scan\ScanRun;

final class IntegrityReportRenderer {
	public function render( ?ScanRun $completed, ?IntegrityStep $progress ): string {
		$html  = '<section aria-labelledby="amsec-integrity"><h2 id="amsec-integrity">Release file integrity</h2>';
		$html .= '<p>On request, this check fetches release checksums from api.wordpress.org and downloads.wordpress.org. Site file contents stay on this server. A checksum difference is not a malware verdict.</p>';
		if ( null !== $completed ) {
			$html .= '<h3>Last completed report</h3><p>Tested <time datetime="' . esc_attr( $completed->finishedAt->format( 'c' ) ) . '">' . esc_html( $completed->finishedAt->format( 'Y-m-d H:i:s' ) . ' UTC' ) . '</time>.</p>';
			$html .= $this->findings( $completed->results, 'Completed integrity findings' );
		}
		if ( null !== $progress ) {
			$cursor = $progress->cursor;
			$html  .= '<h3>Current scan: ' . ( $cursor->partial || $progress->finished ? 'Partial' : 'In progress' ) . '</h3>';
			$html  .= '<p>Started ' . esc_html( ( $cursor->startedAt ?? new \DateTimeImmutable() )->format( 'Y-m-d H:i:s' ) . ' UTC' ) . '. ' . esc_html( (string) $cursor->processed ) . ' files checked; ' . esc_html( (string) $cursor->matched ) . ' matched the published release.</p>';
			if ( array() !== $cursor->packages ) {
				$html .= '<ul>';
				foreach ( $cursor->packages as $package => $counts ) {
					$html .= '<li>' . esc_html( (string) $package ) . ': ' . esc_html( (string) $counts['checked'] ) . ' of ' . esc_html( (string) $counts['total'] ) . ' files checked; ' . esc_html( (string) $counts['matched'] ) . ' matched.</li>';
				}
				$html .= '</ul>';
			}
			$html .= $this->findings( $cursor->findings, 'Current integrity findings' );
		} elseif ( null === $completed ) {
			$html .= '<p>No integrity scan has run yet.</p>';
		}
		return $html . '</section>';
	}

	private function findings( array $findings, string $label ): string {
		if ( array() === $findings ) {
			return '<p>No file differences recorded in this report. Coverage depends on the package and scan status above.</p>';
		}
		$html = '<div class="amazing-security-table-scroll" role="region" tabindex="0" aria-label="' . esc_attr( $label ) . '"><table class="widefat striped"><thead><tr><th scope="col">State</th><th scope="col">Package</th><th scope="col">File</th><th scope="col">Finding</th><th scope="col">Source</th></tr></thead><tbody>';
		foreach ( $findings as $finding ) {
			$html .= '<tr><td>' . esc_html( $finding->state ) . '</td><td>' . esc_html( (string) ( $finding->evidence['package'] ?? '' ) ) . '</td><td>' . esc_html( (string) ( $finding->evidence['path'] ?? '' ) ) . '</td><td>' . esc_html( $finding->summary ) . '</td><td><a href="' . esc_url( $finding->sourceUrl ) . '" target="_blank" rel="noopener noreferrer">Published source</a></td></tr>';
		}
		return $html . '</tbody></table></div>';
	}
}
