<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Integrity\IntegrityStep;
use AmazingPlugins\Security\Scan\ScanRun;

final class IntegrityReportRenderer {
	public function render( ?ScanRun $completed, ?IntegrityStep $progress ): string {
		$html  = '<section aria-labelledby="amsec-integrity"><h2 id="amsec-integrity">' . esc_html__( 'Release file integrity', 'amazing-security' ) . '</h2>';
		$html .= '<p>' . esc_html__( 'On request, this check fetches release checksums from api.wordpress.org and downloads.wordpress.org. Site file contents stay on this server. A checksum difference is not a malware verdict.', 'amazing-security' ) . '</p>';
		if ( null !== $completed ) {
			$html .= '<h3>' . esc_html__( 'Last completed report', 'amazing-security' ) . '</h3><p>' . esc_html__( 'Tested', 'amazing-security' ) . ' <time datetime="' . esc_attr( $completed->finishedAt->format( 'c' ) ) . '">' . esc_html( $completed->finishedAt->format( 'Y-m-d H:i:s' ) . ' UTC' ) . '</time>.</p>';
			$html .= $this->findings( $completed->results, __( 'Completed integrity findings', 'amazing-security' ) );
		}
		if ( null !== $progress ) {
			$cursor = $progress->cursor;
			$html  .= '<h3>' . sprintf(
				/* translators: %s: state of the current integrity scan, either Partial or In progress. */
				esc_html__( 'Current scan: %s', 'amazing-security' ),
				$cursor->partial || $progress->finished ? __( 'Partial', 'amazing-security' ) : __( 'In progress', 'amazing-security' )
			) . '</h3>';
			$html .= '<p>' . sprintf(
				/* translators: 1: time the current integrity scan started, 2: number of files checked, 3: number of checked files that matched the published release. */
				esc_html__( 'Started %1$s. %2$s files checked; %3$s matched the published release.', 'amazing-security' ),
				esc_html( ( $cursor->startedAt ?? new \DateTimeImmutable() )->format( 'Y-m-d H:i:s' ) . ' UTC' ),
				esc_html( (string) $cursor->processed ),
				esc_html( (string) $cursor->matched )
			) . '</p>';
			if ( array() !== $cursor->packages ) {
				$html .= '<ul>';
				foreach ( $cursor->packages as $package => $counts ) {
					$html .= '<li>' . esc_html( (string) $package ) . ': ' . sprintf(
					/* translators: 1: number of files checked, 2: total number of files in the package, 3: number of files that matched. */
						esc_html__( '%1$s of %2$s files checked; %3$s matched.', 'amazing-security' ),
						esc_html( (string) $counts['checked'] ),
						esc_html( (string) $counts['total'] ),
						esc_html( (string) $counts['matched'] )
					) . '</li>';
				}
				$html .= '</ul>';
			}
			$html .= $this->findings( $cursor->findings, __( 'Current integrity findings', 'amazing-security' ) );
		} elseif ( null === $completed ) {
			$html .= '<p>' . esc_html__( 'No integrity scan has run yet.', 'amazing-security' ) . '</p>';
		}
		return $html . '</section>';
	}

	private function findings( array $findings, string $label ): string {
		if ( array() === $findings ) {
			return '<p>' . esc_html__( 'No file differences recorded in this report. Coverage depends on the package and scan status above.', 'amazing-security' ) . '</p>';
		}
		$html = '<div class="amazing-security-table-scroll" role="region" tabindex="0" aria-label="' . esc_attr( $label ) . '"><table class="widefat striped amsec-stacked-table"><thead><tr><th scope="col">' . esc_html__( 'State', 'amazing-security' ) . '</th><th scope="col">' . esc_html__( 'Package', 'amazing-security' ) . '</th><th scope="col">' . esc_html__( 'File', 'amazing-security' ) . '</th><th scope="col">' . esc_html__( 'Finding', 'amazing-security' ) . '</th><th scope="col">' . esc_html__( 'Source', 'amazing-security' ) . '</th></tr></thead><tbody>';
		foreach ( $findings as $finding ) {
			$html .= '<tr><td data-label="' . esc_attr__( 'State', 'amazing-security' ) . '">' . esc_html( $finding->state ) . '</td><td data-label="' . esc_attr__( 'Package', 'amazing-security' ) . '">' . esc_html( (string) ( $finding->evidence['package'] ?? '' ) ) . '</td><td data-label="' . esc_attr__( 'File', 'amazing-security' ) . '">' . esc_html( (string) ( $finding->evidence['path'] ?? '' ) ) . '</td><td data-label="' . esc_attr__( 'Finding', 'amazing-security' ) . '">' . esc_html( $finding->summary ) . '</td><td data-label="' . esc_attr__( 'Source', 'amazing-security' ) . '"><a href="' . esc_url( $finding->sourceUrl ) . '" target="_blank" rel="noopener noreferrer">' . esc_html__( 'Published source', 'amazing-security' ) . '</a></td></tr>';
		}
		return $html . '</tbody></table></div>';
	}
}
