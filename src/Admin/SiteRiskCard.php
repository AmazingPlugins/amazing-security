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
			'plugins:exploited' => __( 'An installed plugin or theme has an open security hole that attackers are using now. Update it.', 'amsec-security-scanner' ),
			'plugins:open-hole' => __( 'An installed plugin or theme has an open security hole. Update it.', 'amsec-security-scanner' ),
			'plugins:watch' => __( 'A plugin or theme has had several serious holes lately. Keep it updated.', 'amsec-security-scanner' ),
			'plugins:off' => __( 'Vulnerability checks are off, so known holes are not looked for.', 'amsec-security-scanner' ),
			'plugins:no-report' => __( 'Installed versions have not been checked for known holes yet.', 'amsec-security-scanner' ),
			'plugins:clear' => __( 'No open holes in installed versions on the last check.', 'amsec-security-scanner' ),
			'files:malware' => __( 'The file scan found code that looks like malware.', 'amsec-security-scanner' ),
			'files:uploads-php' => __( 'There are PHP files in the uploads folder.', 'amsec-security-scanner' ),
			'files:core-changed' => __( 'A WordPress file does not match the official release.', 'amsec-security-scanner' ),
			'files:not-run' => __( 'The malware scan has not finished yet.', 'amsec-security-scanner' ),
			'files:stale' => __( 'The last scan is more than a week old. Scan again.', 'amsec-security-scanner' ),
			'files:clear' => __( 'No malware shapes found on the last scan.', 'amsec-security-scanner' ),
			'bots:all-off' => __( 'Bot controls, the scanner guard and rate limits are all off.', 'amsec-security-scanner' ),
			'bots:watch-only' => __( 'Bot protection is watching but not blocking anything yet.', 'amsec-security-scanner' ),
			'bots:on' => __( 'At least one bot protection is blocking.', 'amsec-security-scanner' ),
			'ai:assistant-plain' => __( 'AI assistant access is on while the admin is not on HTTPS.', 'amsec-security-scanner' ),
			'ai:crawlers' => __( 'AI crawlers are not told whether they may read the site.', 'amsec-security-scanner' ),
			'ai:no-guide' => __( 'There is no llms.txt guide for AI tools.', 'amsec-security-scanner' ),
			'ai:ready' => __( 'AI access and crawler rules are set.', 'amsec-security-scanner' ),
			'signin:off' => __( 'Sign-in attempts are not limited, so passwords can be guessed.', 'amsec-security-scanner' ),
			'signin:watch' => __( 'Failed sign-ins are recorded but not blocked yet.', 'amsec-security-scanner' ),
			'signin:on' => __( 'Repeated failed sign-ins are blocked.', 'amsec-security-scanner' ),
			default => __( 'This could not be read from the last scan.', 'amsec-security-scanner' ),
		};
	}

	/** @param list<array{area: string, status: string, reason: string}> $rows */
	public static function render( array $rows ): string {
		$areas    = array(
			'plugins' => array( __( 'Plugins and themes', 'amsec-security-scanner' ), 'amsec-vulnerabilities', __( 'Check versions', 'amsec-security-scanner' ) ),
			'files'   => array( __( 'Malware and files', 'amsec-security-scanner' ), 'amsec-files', __( 'Open files', 'amsec-security-scanner' ) ),
			'bots'    => array( __( 'Bot protection', 'amsec-security-scanner' ), 'amsec-traffic-guard', __( 'Open traffic', 'amsec-security-scanner' ) ),
			'ai'      => array( __( 'AI readiness', 'amsec-security-scanner' ), 'amsec-assistant', __( 'Open AI settings', 'amsec-security-scanner' ) ),
			'signin'  => array( __( 'Sign-in', 'amsec-security-scanner' ), 'amsec-accounts#sign-in', __( 'Open sign-in', 'amsec-security-scanner' ) ),
		);
		$statuses = array(
			SiteRisk::GOOD  => array( __( 'Good', 'amsec-security-scanner' ), ' is-on' ),
			SiteRisk::CHECK => array( __( 'Check', 'amsec-security-scanner' ), '' ),
			SiteRisk::RISK  => array( __( 'Risk', 'amsec-security-scanner' ), ' is-risk' ),
		);
		$html     = '<section class="amsec-overview amsec-risk-card" aria-labelledby="amsec-risk-title"><h2 id="amsec-risk-title">' . esc_html__( 'Site risk at a glance', 'amsec-security-scanner' ) . '</h2><ul class="amsec-risk-list">';
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
