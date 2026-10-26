<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Bots\BotHooks;
use AmazingPlugins\Security\Bots\RateLimiter;
use AmazingPlugins\Security\Bots\ScannerGuard;
use AmazingPlugins\Security\Findings\SiteRisk;

/** Renders SiteRisk rows as the card at the top of the Scan results. */
final class SiteRiskCard {
	/** @return array{0: string, 1: string, 2: string} Bot control, scanner guard and rate limit modes. */
	public static function botModes(): array {
		return array( ( new BotHooks() )->mode(), ScannerGuard::mode(), (string) RateLimiter::settings()['mode'] );
	}

	/** Plain text for a row's reason key, also used by the assistant output. */
	public static function reason( string $area, string $reason ): string {
		return match ( $area . ':' . $reason ) {
			'plugins:exploited' => __( 'An installed plugin or theme has an open security hole that attackers are using now. Update it.', 'amazing-security-scanner' ),
			'plugins:open-hole' => __( 'An installed plugin or theme has an open security hole. Update it.', 'amazing-security-scanner' ),
			'plugins:watch' => __( 'A plugin or theme has had several serious holes lately. Keep it updated.', 'amazing-security-scanner' ),
			'plugins:off' => __( 'Vulnerability checks are off, so known holes are not looked for.', 'amazing-security-scanner' ),
			'plugins:no-report' => __( 'Installed versions have not been checked for known holes yet.', 'amazing-security-scanner' ),
			'plugins:clear' => __( 'No open holes in installed versions on the last check.', 'amazing-security-scanner' ),
			'files:malware' => __( 'The file scan found code that looks like malware.', 'amazing-security-scanner' ),
			'files:uploads-php' => __( 'There are PHP files in the uploads folder.', 'amazing-security-scanner' ),
			'files:core-changed' => __( 'A WordPress file does not match the official release.', 'amazing-security-scanner' ),
			'files:not-run' => __( 'The malware scan has not finished yet.', 'amazing-security-scanner' ),
			'files:stale' => __( 'The last scan is more than a week old. Scan again.', 'amazing-security-scanner' ),
			'files:clear' => __( 'No malware shapes found on the last scan.', 'amazing-security-scanner' ),
			'bots:all-off' => __( 'Bot controls, the scanner guard and rate limits are all off.', 'amazing-security-scanner' ),
			'bots:watch-only' => __( 'Bot protection is watching but not blocking anything yet.', 'amazing-security-scanner' ),
			'bots:on' => __( 'At least one bot protection is blocking.', 'amazing-security-scanner' ),
			'ai:assistant-plain' => __( 'AI assistant access is on while the admin is not on HTTPS.', 'amazing-security-scanner' ),
			'ai:crawlers' => __( 'AI crawlers are not told whether they may read the site.', 'amazing-security-scanner' ),
			'ai:no-guide' => __( 'There is no llms.txt guide for AI tools.', 'amazing-security-scanner' ),
			'ai:ready' => __( 'AI access and crawler rules are set.', 'amazing-security-scanner' ),
			'signin:off' => __( 'Sign-in attempts are not limited, so passwords can be guessed.', 'amazing-security-scanner' ),
			'signin:watch' => __( 'Failed sign-ins are recorded but not blocked yet.', 'amazing-security-scanner' ),
			'signin:on' => __( 'Repeated failed sign-ins are blocked.', 'amazing-security-scanner' ),
			default => __( 'This could not be read from the last scan.', 'amazing-security-scanner' ),
		};
	}

	/** @param list<array{area: string, status: string, reason: string}> $rows */
	public static function render( array $rows ): string {
		$areas    = array(
			'plugins' => array( __( 'Plugins and themes', 'amazing-security-scanner' ), 'amsec-vulnerabilities', __( 'Check versions', 'amazing-security-scanner' ) ),
			'files'   => array( __( 'Malware and files', 'amazing-security-scanner' ), 'amsec-files', __( 'Open files', 'amazing-security-scanner' ) ),
			'bots'    => array( __( 'Bot protection', 'amazing-security-scanner' ), 'amsec-traffic-guard', __( 'Open traffic', 'amazing-security-scanner' ) ),
			'ai'      => array( __( 'AI readiness', 'amazing-security-scanner' ), 'amsec-assistant', __( 'Open AI settings', 'amazing-security-scanner' ) ),
			'signin'  => array( __( 'Sign-in', 'amazing-security-scanner' ), 'amsec-accounts#sign-in', __( 'Open sign-in', 'amazing-security-scanner' ) ),
		);
		$statuses = array(
			SiteRisk::GOOD  => array( __( 'Good', 'amazing-security-scanner' ), ' is-on' ),
			SiteRisk::CHECK => array( __( 'Check', 'amazing-security-scanner' ), '' ),
			SiteRisk::RISK  => array( __( 'Risk', 'amazing-security-scanner' ), ' is-risk' ),
		);
		$html     = '<section class="amsec-overview amsec-risk-card" aria-labelledby="amsec-risk-title"><h2 id="amsec-risk-title">' . esc_html__( 'Site risk at a glance', 'amazing-security-scanner' ) . '</h2><ul class="amsec-risk-list">';
		foreach ( $rows as $row ) {
			if ( ! isset( $areas[ $row['area'] ], $statuses[ $row['status'] ] ) ) {
				continue;
			}
			list( $label, $slug, $link ) = $areas[ $row['area'] ];
			list( $word, $class )        = $statuses[ $row['status'] ];
			$html                       .= '<li class="amsec-risk-row"><span class="amsec-pill' . $class . '">' . esc_html( $word ) . '</span><span class="amsec-risk-text"><strong>' . esc_html( $label ) . '</strong> ' . esc_html( self::reason( $row['area'], $row['reason'] ) ) . '</span><a href="' . esc_url( admin_url( 'admin.php?page=' . $slug ) ) . '">' . esc_html( $link ) . '</a></li>';
		}
		return $html . '</ul></section>';
	}
}
