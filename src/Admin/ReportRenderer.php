<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

use AmazingPlugins\Security\Scan\ScanRun;

final class ReportRenderer {
	public function render( ScanRun $run ): string {
		$html  = '<p>Last scan: <time datetime="' . esc_attr( $run->finishedAt->format( 'c' ) ) . '">' . esc_html( $run->finishedAt->format( 'Y-m-d H:i:s' ) . ' UTC' ) . '</time>. ' . esc_html( (string) $run->unknownCount() ) . ' unknown checks. ';
		$html .= $run->partial ? 'Coverage is partial.</p>' : 'All registered checks completed.</p>';
		$html .= '<div class="amazing-security-table-scroll" role="region" tabindex="0" aria-label="Security findings"><table class="widefat striped"><thead><tr><th scope="col">Check</th><th scope="col">State</th><th scope="col">Finding</th><th scope="col">Source</th></tr></thead><tbody>';
		foreach ( $run->results as $result ) {
			$html .= '<tr><th scope="row">' . esc_html( $result->checkId ) . '</th><td>' . esc_html( $result->state ) . '</td><td>' . esc_html( $result->summary ) . '</td><td><a href="' . esc_url( $result->sourceUrl ) . '" target="_blank" rel="noopener noreferrer">WordPress guidance</a></td></tr>';
		}
		return $html . '</tbody></table></div>';
	}
}
