<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\FileScan\BundledRulePack;
use AmazingPlugins\Security\FileScan\FileScanReport;
use AmazingPlugins\Security\FileScan\FileScanStep;
use AmazingPlugins\Security\FileScan\RuleGuidance;
use DateTimeImmutable;

final class FileScanReportRenderer {
	public function __construct( private readonly string $actionUrl = '', private readonly string $noteNonce = '', private readonly array $notes = array(), private readonly string $title = '', private readonly string $anchor = 'amsec-file-scan' ) {}

	public function render( ?FileScanReport $completed, ?FileScanStep $progress, array $history ): string {
		$version  = ( new BundledRulePack() )->version();
		$released = DateTimeImmutable::createFromFormat( '!Y.m.d', substr( $version, 0, 10 ) );
		$age      = false === $released ? 0 : max( 0, (int) floor( ( time() - $released->getTimestamp() ) / 86400 ) );
		$html     = '<section class="amsec-file-scan" aria-labelledby="' . esc_attr( $this->anchor ) . '"><div class="amsec-file-heading"><div><h2 id="' . esc_attr( $this->anchor ) . '">' . esc_html( '' !== $this->title ? $this->title : __( 'Suspicious files', 'amsec-security-scanner' ) ) . '</h2><p>' . esc_html(
			'' !== $this->title
				? __( 'Runs with every Scan. Reads plugins, themes, uploads, mu-plugins and loose PHP files. A match needs review; no match does not prove the site is clean.', 'amsec-security-scanner' )
				: __( 'Looks for extra files in plugins, themes and uploads that a release does not contain. A match needs review; no match does not prove the site is clean.', 'amsec-security-scanner' )
		) . '</p></div><span class="amsec-file-rule-age">' . sprintf(
				/* translators: 1: version of the bundled rule pack, 2: age of the rule pack in days. */
			esc_html( _n( 'Bundled rules %1$s (%2$s day old)', 'Bundled rules %1$s (%2$s days old)', $age, 'amsec-security-scanner' ) ),
			esc_html( $version ),
			esc_html( (string) $age )
		) . '</span></div>';
		if ( null === $completed && null === $progress ) {
			return $html . '<p class="amsec-file-empty">' . esc_html__( 'No file scan has run. Start one to check for extra files and the bundled suspicious-code patterns.', 'amsec-security-scanner' ) . '</p></section>';
		}
		if ( null !== $progress ) {
			$cursor = $progress->cursor;
			$label  = $cursor->partial ? __( 'Partial coverage', 'amsec-security-scanner' ) : ( $progress->finished ? __( 'Scan finished', 'amsec-security-scanner' ) : __( 'Scan in progress', 'amsec-security-scanner' ) );
			$html  .= '<div class="amsec-file-status amsec-file-status-' . esc_attr( $cursor->partial ? 'partial' : 'progress' ) . '" role="status"><strong>' . esc_html( $label ) . '</strong><span>' . ( $progress->finished ? '' : esc_html__( 'Scan in progress.', 'amsec-security-scanner' ) . ' ' ) . sprintf(
				/* translators: 1: number of files checked, 2: number of files that could not be checked. */
				esc_html__( '%1$s files checked. %2$s could not be checked.', 'amsec-security-scanner' ),
				esc_html( (string) $cursor->processed ),
				esc_html( (string) $cursor->unknown )
			) . '</span></div>';
			$html .= $this->coverage( $cursor->processed, $cursor->verified, $cursor->scanned, $cursor->extra, $cursor->excluded, $cursor->unknown, $cursor->omitted );
			$html .= $this->findings( $cursor->findings, __( 'Current file scan findings', 'amsec-security-scanner' ) );
		}
		if ( null !== $completed ) {
			$html .= '<h3>' . esc_html__( 'Last finished scan', 'amsec-security-scanner' ) . '</h3><p>' . sprintf(
				/* translators: 1: HTML time element with the scan finish time, 2: number of files checked. */
				esc_html__( 'Tested %1$s. %2$s files checked.', 'amsec-security-scanner' ),
				'<time datetime="' . esc_attr( $completed->finishedAt->format( 'c' ) ) . '">' . esc_html( $completed->finishedAt->format( 'Y-m-d H:i:s' ) . ' UTC' ) . '</time>',
				esc_html( (string) $completed->processed )
			) . '</p>';
			if ( null === $progress ) {
				$html .= '<div class="amsec-file-status amsec-file-status-' . esc_attr( $completed->partial ? 'partial' : 'progress' ) . '" role="status"><strong>' . esc_html( $completed->partial ? __( 'Partial coverage', 'amsec-security-scanner' ) : ( 'warn' === $completed->state ? __( 'Findings need review', 'amsec-security-scanner' ) : __( 'Scan finished', 'amsec-security-scanner' ) ) ) . '</strong></div>';
				$html .= $this->coverage( $completed->processed, $completed->verified, $completed->scanned, $completed->extra, $completed->excluded, $completed->unknown, $completed->omitted );
			}
			$html .= $this->findings( $completed->findings, __( 'Completed file scan findings', 'amsec-security-scanner' ), null === $progress );
		}
		$older = array_values( array_filter( $history, static fn( mixed $report ): bool => $report instanceof FileScanReport && ( null === $completed || $report->scanId !== $completed->scanId ) ) );
		if ( array() !== $older ) {
			$html .= '<details class="amsec-file-history"><summary>' . esc_html__( 'Earlier warnings', 'amsec-security-scanner' ) . '</summary><ul>';
			foreach ( $older as $report ) {
				$count = count( $report->findings );
				$html .= '<li><details><summary><time datetime="' . esc_attr( $report->finishedAt->format( 'c' ) ) . '">' . esc_html( $report->finishedAt->format( 'Y-m-d H:i:s' ) . ' UTC' ) . '</time>: ' . esc_html( sprintf( /* translators: %d: number of findings. */ _n( '%d finding', '%d findings', $count, 'amsec-security-scanner' ), $count ) ) . '</summary><ul>';
				foreach ( $report->findings as $finding ) {
					$id      = (string) ( $finding['id'] ?? '' );
					$present = false;
					foreach ( $completed?->findings ?? array() as $current ) {
						$present = $present || (string) ( $current['id'] ?? '' ) === $id;
					}
					$status = null === $completed || $completed->finishedAt <= $report->finishedAt ? __( 'No later complete comparison available', 'amsec-security-scanner' ) : ( $completed->partial ? __( 'Current status unknown; latest scan was partial', 'amsec-security-scanner' ) : ( $present ? __( 'Still reported in the last complete scan', 'amsec-security-scanner' ) : __( 'Not reported in the last complete scan', 'amsec-security-scanner' ) ) );
					$html  .= '<li><strong>' . esc_html( (string) ( $finding['package'] ?? '' ) ) . '</strong> <code>' . esc_html( (string) ( $finding['path'] ?? '' ) ) . '</code> ' . esc_html( (string) ( $finding['rule_id'] ?? '' ) ) . ' <time datetime="' . esc_attr( (string) ( $finding['tested_at'] ?? '' ) ) . '">' . esc_html( (string) ( $finding['tested_at'] ?? '' ) ) . '</time>. ' . esc_html( $status ) . '.</li>';
				}
				$html .= '</ul></details></li>';
			}
			$html .= '</ul></details>';
		}
		return $html . '</section>';
	}

	private function coverage( int $processed, int $verified, int $scanned, int $extra, int $excluded, int $unknown, int $omitted ): string {
		return '<dl class="amsec-file-coverage"><div><dt>' . esc_html__( 'Files seen', 'amsec-security-scanner' ) . '</dt><dd>' . esc_html( (string) $processed ) . '</dd></div><div><dt>' . esc_html__( 'Release-matched PHP', 'amsec-security-scanner' ) . '</dt><dd>' . esc_html( (string) $verified ) . '</dd></div><div><dt>' . esc_html__( 'Code checked', 'amsec-security-scanner' ) . '</dt><dd>' . esc_html( (string) $scanned ) . '</dd></div><div><dt>' . esc_html__( 'Extra files', 'amsec-security-scanner' ) . '</dt><dd>' . esc_html( (string) $extra ) . '</dd></div><div><dt>' . esc_html__( 'Excluded', 'amsec-security-scanner' ) . '</dt><dd>' . esc_html( (string) $excluded ) . '</dd></div><div><dt>' . esc_html__( 'Could not check', 'amsec-security-scanner' ) . '</dt><dd>' . esc_html( (string) $unknown ) . '</dd></div>' . ( $omitted > 0 ? '<div><dt>' . esc_html__( 'Findings omitted', 'amsec-security-scanner' ) . '</dt><dd>' . esc_html( (string) $omitted ) . '</dd></div>' : '' ) . '</dl>';
	}

	private function findings( array $findings, string $label, bool $allowNotes = true ): string {
		if ( array() === $findings ) {
			return '<p>' . esc_html__( 'No findings in this report. Review its coverage above.', 'amsec-security-scanner' ) . '</p>';
		}
		$html = '<div class="amsec-file-findings" aria-label="' . esc_attr( $label ) . '"><h3>' . esc_html( $label ) . '</h3><ol>';
		foreach ( $findings as $finding ) {
			$kind  = (string) ( $finding['kind'] ?? '' );
			$title = 'suspected' === $kind ? __( 'Suspected code', 'amsec-security-scanner' ) : ( 'extra' === $kind ? __( 'Review file', 'amsec-security-scanner' ) : ( 'package' === $kind ? __( 'Release unavailable', 'amsec-security-scanner' ) : __( 'Could not check file', 'amsec-security-scanner' ) ) );
			$html .= '<li class="amsec-file-finding"><div class="amsec-file-finding-top"><strong>' . esc_html( $title ) . '</strong><span>' . esc_html( (string) ( $finding['rule_id'] ?? '' ) ) . '</span></div>';
			$html .= '<span class="amsec-file-package">' . esc_html( self::packageName( (string) ( $finding['package'] ?? '' ) ) ) . '</span>';
			if ( 'package' === $kind ) {
				$reason = self::reason( (string) ( $finding['reason'] ?? '' ) );
				$html  .= '' !== $reason ? '<span class="amsec-file-reason">' . esc_html( $reason ) . '</span>' : '';
			} else {
				$html .= '<code>' . esc_html( (string) ( $finding['path'] ?? '' ) ) . '</code>';
			}
			if ( (int) ( $finding['line'] ?? 0 ) > 0 ) {
				$html .= '<span class="amsec-file-line">' . sprintf(
						/* translators: %s: line number in the flagged file. */
					esc_html__( 'Line %s', 'amsec-security-scanner' ),
					esc_html( (string) (int) $finding['line'] )
				) . '</span>';
			}
			$html .= '<p>' . esc_html( (string) ( $finding['summary'] ?? '' ) ) . '</p>';
			if ( 'unscanned' === $kind && 'rule_memory_limit' === ( $finding['reason'] ?? '' ) ) {
				$html .= '<p>' . esc_html__( 'This file exceeded the code check memory budget. It has not been cleared. Compare it with its trusted release or ask your developer to inspect it separately.', 'amsec-security-scanner' ) . '</p>';
			}
			if ( 'suspected' === $kind ) {
				$html .= '<details class="amsec-rule-guidance"><summary>' . esc_html__( 'Why this needs review and what to do', 'amsec-security-scanner' ) . '</summary><p>' . esc_html( RuleGuidance::forRule( (string) ( $finding['rule_id'] ?? '' ) ) ) . '</p><p>' . esc_html__( 'Back up the site before making changes. Compare the exact installed version with its trusted release, and ask the plugin or theme developer to review differences. Do not delete a file based only on this match. Use the review note below to record your assessment.', 'amsec-security-scanner' ) . '</p></details>';
			}
			$id     = (string) ( $finding['id'] ?? '' );
			$formId = 'amsec-note-' . substr( hash( 'sha256', $label ), 0, 8 ) . '-' . $id;
			if ( isset( $this->notes[ $id ] ) ) {
				$html .= '<p class="amsec-file-note"><strong>' . esc_html__( 'Review note:', 'amsec-security-scanner' ) . '</strong> ' . esc_html( (string) $this->notes[ $id ] ) . '</p>';
			}
			if ( $allowNotes && 'package' !== $kind && '' !== $this->actionUrl && '' !== $this->noteNonce && preg_match( '/^[a-f0-9]{32}$/D', $id ) ) {
				$html .= '<form action="' . esc_url( $this->actionUrl ) . '" method="post" class="amsec-file-note-form"><input type="hidden" name="action" value="amsec_security_scanner_file_scan_note"><input type="hidden" name="finding_id" value="' . esc_attr( $id ) . '"><input type="hidden" name="_wpnonce" value="' . esc_attr( $this->noteNonce ) . '"><label for="' . esc_attr( $formId ) . '">' . esc_html__( 'False-positive review note', 'amsec-security-scanner' ) . '</label><textarea id="' . esc_attr( $formId ) . '" name="note" maxlength="500" rows="2"></textarea><button type="submit" class="button button-secondary">' . esc_html__( 'Save review note', 'amsec-security-scanner' ) . '</button></form>';
			}
			$html .= '</li>';
		}
		return $html . '</ol></div>';
	}

	/** Turns "theme:twentytwentyfive:1.4" into "Theme twentytwentyfive 1.4". */
	public static function packageName( string $package ): string {
		if ( 1 !== preg_match( '/^(plugin|theme|core):([^:]*):(.*)$/D', $package, $m ) ) {
			return $package;
		}
		$type = match ( $m[1] ) {
			'plugin' => __( 'Plugin', 'amsec-security-scanner' ),
			'theme'  => __( 'Theme', 'amsec-security-scanner' ),
			default  => __( 'WordPress core', 'amsec-security-scanner' ),
		};
		return trim( $type . ' ' . $m[2] . ' ' . $m[3] );
	}

	public static function reason( string $code ): string {
		return match ( $code ) {
			'package_limit'              => __( 'Each scan compares at most three themes with their release.', 'amsec-security-scanner' ),
			'non_wordpress_org_origin'   => __( 'Not from WordPress.org, so there is no published release to compare.', 'amsec-security-scanner' ),
			'unsupported_child_theme'    => __( 'Child themes have no published release to compare.', 'amsec-security-scanner' ),
			'unsupported_local_path'     => __( 'Installed from a local path, so there is no published release to compare.', 'amsec-security-scanner' ),
			'theme_provider_unavailable' => __( 'WordPress.org could not be reached for this theme.', 'amsec-security-scanner' ),
			''                           => '',
			default                      => __( 'WordPress.org did not return a release this scan could use.', 'amsec-security-scanner' ),
		};
	}
}
