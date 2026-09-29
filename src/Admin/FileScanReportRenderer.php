<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

use AmazingPlugins\Security\FileScan\BundledRulePack;
use AmazingPlugins\Security\FileScan\FileScanReport;
use AmazingPlugins\Security\FileScan\FileScanStep;
use DateTimeImmutable;

final class FileScanReportRenderer {
	public function __construct( private readonly string $actionUrl = '', private readonly string $noteNonce = '', private readonly array $notes = array() ) {}

	public function render( ?FileScanReport $completed, ?FileScanStep $progress, array $history ): string {
		$version  = ( new BundledRulePack() )->version();
		$released = DateTimeImmutable::createFromFormat( '!Y.m.d', substr( $version, 0, 10 ) );
		$age      = false === $released ? 0 : max( 0, (int) floor( ( time() - $released->getTimestamp() ) / 86400 ) );
		$html     = '<section class="amsec-file-scan" aria-labelledby="amsec-file-scan"><div class="amsec-file-heading"><div><h2 id="amsec-file-scan">Suspicious files</h2><p>Checks unfamiliar PHP files on this site. A match needs review; no match does not prove the site is clean.</p></div><span class="amsec-file-rule-age">Bundled rules ' . esc_html( $version ) . ' (' . esc_html( (string) $age ) . ' days old)</span></div>';
		if ( null === $completed && null === $progress ) {
			return $html . '<p class="amsec-file-empty">No file scan has run. Start one to check for extra files and three suspicious code patterns.</p></section>';
		}
		if ( null !== $progress ) {
			$cursor = $progress->cursor;
			$label  = $cursor->partial ? 'Partial coverage' : ( $progress->finished ? 'Scan finished' : 'Scan in progress' );
			$html  .= '<div class="amsec-file-status amsec-file-status-' . esc_attr( $cursor->partial ? 'partial' : 'progress' ) . '" role="status"><strong>' . esc_html( $label ) . '</strong><span>' . ( $progress->finished ? '' : 'Scan in progress. ' ) . esc_html( (string) $cursor->processed ) . ' files checked. ' . esc_html( (string) $cursor->unknown ) . ' could not be checked.</span></div>';
			$html  .= $this->coverage( $cursor->processed, $cursor->verified, $cursor->scanned, $cursor->extra, $cursor->excluded, $cursor->unknown, $cursor->omitted );
			$html  .= $this->findings( $cursor->findings, 'Current file scan findings' );
		}
		if ( null !== $completed ) {
			$html .= '<h3>Last finished scan</h3><p>Tested <time datetime="' . esc_attr( $completed->finishedAt->format( 'c' ) ) . '">' . esc_html( $completed->finishedAt->format( 'Y-m-d H:i:s' ) . ' UTC' ) . '</time>. ' . esc_html( (string) $completed->processed ) . ' files checked.</p>';
			if ( null === $progress ) {
				$html .= '<div class="amsec-file-status amsec-file-status-' . esc_attr( $completed->partial ? 'partial' : 'progress' ) . '" role="status"><strong>' . esc_html( $completed->partial ? 'Partial coverage' : ( 'warn' === $completed->state ? 'Findings need review' : 'Scan finished' ) ) . '</strong></div>';
				$html .= $this->coverage( $completed->processed, $completed->verified, $completed->scanned, $completed->extra, $completed->excluded, $completed->unknown, $completed->omitted );
			}
			$html .= $this->findings( $completed->findings, 'Completed file scan findings', null === $progress );
		}
		$older = array_values( array_filter( $history, static fn( mixed $report ): bool => $report instanceof FileScanReport && ( null === $completed || $report->scanId !== $completed->scanId ) ) );
		if ( array() !== $older ) {
			$html .= '<details class="amsec-file-history"><summary>Earlier warnings</summary><ul>';
			foreach ( $older as $report ) {
				$count = count( $report->findings );
				$html .= '<li><details><summary><time datetime="' . esc_attr( $report->finishedAt->format( 'c' ) ) . '">' . esc_html( $report->finishedAt->format( 'Y-m-d H:i:s' ) . ' UTC' ) . '</time>: ' . esc_html( (string) $count ) . ' ' . ( 1 === $count ? 'finding' : 'findings' ) . '</summary><ul>';
				foreach ( $report->findings as $finding ) {
					$id      = (string) ( $finding['id'] ?? '' );
					$present = false;
					foreach ( $completed?->findings ?? array() as $current ) {
						$present = $present || (string) ( $current['id'] ?? '' ) === $id;
					}
					$status = null === $completed ? 'No later complete comparison available' : ( $completed->partial ? 'Current status unknown; latest scan was partial' : ( $present ? 'Still reported in the last complete scan' : 'Not reported in the last complete scan' ) );
					$html  .= '<li><strong>' . esc_html( (string) ( $finding['package'] ?? '' ) ) . '</strong> <code>' . esc_html( (string) ( $finding['path'] ?? '' ) ) . '</code> ' . esc_html( (string) ( $finding['rule_id'] ?? '' ) ) . ' <time datetime="' . esc_attr( (string) ( $finding['tested_at'] ?? '' ) ) . '">' . esc_html( (string) ( $finding['tested_at'] ?? '' ) ) . '</time>. ' . esc_html( $status ) . '.</li>';
				}
				$html .= '</ul></details></li>';
			}
			$html .= '</ul></details>';
		}
		return $html . '</section>';
	}

	private function coverage( int $processed, int $verified, int $scanned, int $extra, int $excluded, int $unknown, int $omitted ): string {
		return '<dl class="amsec-file-coverage"><div><dt>Files seen</dt><dd>' . esc_html( (string) $processed ) . '</dd></div><div><dt>Release-matched PHP</dt><dd>' . esc_html( (string) $verified ) . '</dd></div><div><dt>Code checked</dt><dd>' . esc_html( (string) $scanned ) . '</dd></div><div><dt>Extra files</dt><dd>' . esc_html( (string) $extra ) . '</dd></div><div><dt>Excluded</dt><dd>' . esc_html( (string) $excluded ) . '</dd></div><div><dt>Could not check</dt><dd>' . esc_html( (string) $unknown ) . '</dd></div>' . ( $omitted > 0 ? '<div><dt>Findings omitted</dt><dd>' . esc_html( (string) $omitted ) . '</dd></div>' : '' ) . '</dl>';
	}

	private function findings( array $findings, string $label, bool $allowNotes = true ): string {
		if ( array() === $findings ) {
			return '<p>No findings in this report. Review its coverage above.</p>';
		}
		$html = '<div class="amsec-file-findings" aria-label="' . esc_attr( $label ) . '"><h3>' . esc_html( $label ) . '</h3><ol>';
		foreach ( $findings as $finding ) {
			$kind  = (string) ( $finding['kind'] ?? '' );
			$title = 'suspected' === $kind ? 'Suspected code' : ( 'extra' === $kind ? 'Review file' : ( 'package' === $kind ? 'Release unavailable' : 'Could not check file' ) );
			$html .= '<li class="amsec-file-finding"><div class="amsec-file-finding-top"><strong>' . esc_html( $title ) . '</strong><span>' . esc_html( (string) ( $finding['rule_id'] ?? '' ) ) . '</span></div>';
			$html .= '<span class="amsec-file-package">' . esc_html( (string) ( $finding['package'] ?? '' ) ) . '</span>';
			if ( 'package' === $kind ) {
				$html .= '<span class="amsec-file-reason">' . esc_html( (string) ( $finding['reason'] ?? '' ) ) . '</span>';
			} else {
				$html .= '<code>' . esc_html( (string) ( $finding['path'] ?? '' ) ) . '</code>';
			}
			if ( (int) ( $finding['line'] ?? 0 ) > 0 ) {
				$html .= '<span class="amsec-file-line">Line ' . esc_html( (string) (int) $finding['line'] ) . '</span>';
			}
			$html  .= '<p>' . esc_html( (string) ( $finding['summary'] ?? '' ) ) . '</p>';
			$id     = (string) ( $finding['id'] ?? '' );
			$formId = 'amsec-note-' . substr( hash( 'sha256', $label ), 0, 8 ) . '-' . $id;
			if ( isset( $this->notes[ $id ] ) ) {
				$html .= '<p class="amsec-file-note"><strong>Review note:</strong> ' . esc_html( (string) $this->notes[ $id ] ) . '</p>';
			}
			if ( $allowNotes && '' !== $this->actionUrl && '' !== $this->noteNonce && preg_match( '/^[a-f0-9]{32}$/D', $id ) ) {
				$html .= '<form action="' . esc_url( $this->actionUrl ) . '" method="post" class="amsec-file-note-form"><input type="hidden" name="action" value="amazing_security_file_scan_note"><input type="hidden" name="finding_id" value="' . esc_attr( $id ) . '"><input type="hidden" name="_wpnonce" value="' . esc_attr( $this->noteNonce ) . '"><label for="' . esc_attr( $formId ) . '">False-positive review note</label><textarea id="' . esc_attr( $formId ) . '" name="note" maxlength="500" rows="2"></textarea><button type="submit" class="button button-secondary">Save review note</button></form>';
			}
			$html .= '</li>';
		}
		return $html . '</ol></div>';
	}
}
