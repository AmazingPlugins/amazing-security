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
			'plugins:exploited' => __( 'An installed plugin or theme has an open security hole that attackers are using now. Update it.', 'ironlatch-security-scanner' ),
			'plugins:open-hole' => __( 'An installed plugin or theme has an open security hole. Update it.', 'ironlatch-security-scanner' ),
			'plugins:watch' => __( 'A plugin or theme has had several serious holes lately. Keep it updated.', 'ironlatch-security-scanner' ),
			'plugins:off' => __( 'Vulnerability checks are off, so known holes are not looked for.', 'ironlatch-security-scanner' ),
			'plugins:no-report' => __( 'Installed versions have not been checked for known holes yet.', 'ironlatch-security-scanner' ),
			'plugins:clear' => __( 'No open holes in installed versions on the last check.', 'ironlatch-security-scanner' ),
			'files:malware' => __( 'The file scan found code that looks like malware.', 'ironlatch-security-scanner' ),
			'files:uploads-php' => __( 'There are PHP files in the uploads folder.', 'ironlatch-security-scanner' ),
			'files:core-changed' => __( 'A WordPress file does not match the official release.', 'ironlatch-security-scanner' ),
			'files:not-run' => __( 'The malware scan has not finished yet.', 'ironlatch-security-scanner' ),
			'files:stale' => __( 'The last scan is more than a week old. Scan again.', 'ironlatch-security-scanner' ),
			'files:clear' => __( 'No malware shapes found on the last scan.', 'ironlatch-security-scanner' ),
			'bots:all-off' => __( 'Bot controls, the scanner guard and rate limits are all off.', 'ironlatch-security-scanner' ),
			'bots:watch-only' => __( 'Bot protection is watching but not blocking anything yet.', 'ironlatch-security-scanner' ),
			'bots:on' => __( 'At least one bot protection is blocking.', 'ironlatch-security-scanner' ),
			'ai:assistant-plain' => __( 'AI agent access is on while the admin is not on HTTPS.', 'ironlatch-security-scanner' ),
			'ai:crawlers' => __( 'AI crawlers are not told whether they may read the site.', 'ironlatch-security-scanner' ),
			'ai:no-guide' => __( 'There is no llms.txt guide for AI tools.', 'ironlatch-security-scanner' ),
			'ai:ready' => __( 'AI access and crawler rules are set.', 'ironlatch-security-scanner' ),
			'signin:off' => __( 'Sign-in attempts are not limited, so passwords can be guessed.', 'ironlatch-security-scanner' ),
			'signin:watch' => __( 'Failed sign-ins are recorded but not blocked yet.', 'ironlatch-security-scanner' ),
			'signin:on' => __( 'Repeated failed sign-ins are blocked.', 'ironlatch-security-scanner' ),
			default => __( 'This could not be read from the last scan.', 'ironlatch-security-scanner' ),
		};
	}

	/** @param list<array{area: string, status: string, reason: string}> $rows */
	public static function render( array $rows ): string {
		$areas    = array(
			'plugins' => array( __( 'Plugins and themes', 'ironlatch-security-scanner' ), 'ironlatch-vulnerabilities', __( 'Check versions', 'ironlatch-security-scanner' ) ),
			'files'   => array( __( 'Malware and files', 'ironlatch-security-scanner' ), 'ironlatch-files', __( 'Open files', 'ironlatch-security-scanner' ) ),
			'bots'    => array( __( 'Bot protection', 'ironlatch-security-scanner' ), 'ironlatch-traffic-guard', __( 'Open traffic', 'ironlatch-security-scanner' ) ),
			'ai'      => array( __( 'AI readiness', 'ironlatch-security-scanner' ), 'ironlatch-assistant', __( 'Open AI settings', 'ironlatch-security-scanner' ) ),
			'signin'  => array( __( 'Sign-in', 'ironlatch-security-scanner' ), 'ironlatch-accounts#sign-in', __( 'Open sign-in', 'ironlatch-security-scanner' ) ),
		);
		$statuses = array(
			SiteRisk::GOOD  => array( __( 'Good', 'ironlatch-security-scanner' ), ' is-on' ),
			SiteRisk::CHECK => array( __( 'Check', 'ironlatch-security-scanner' ), '' ),
			SiteRisk::RISK  => array( __( 'Risk', 'ironlatch-security-scanner' ), ' is-risk' ),
		);
		$html     = '<section class="ironlatch-overview ironlatch-risk-card" aria-labelledby="ironlatch-risk-title"><h2 id="ironlatch-risk-title">' . esc_html__( 'Site risk at a glance', 'ironlatch-security-scanner' ) . '</h2><ul class="ironlatch-risk-list">';
		foreach ( $rows as $row ) {
			if ( ! isset( $areas[ $row['area'] ], $statuses[ $row['status'] ] ) ) {
				continue;
			}
			list( $label, $slug, $link ) = $areas[ $row['area'] ];
			list( $word, $class )        = $statuses[ $row['status'] ];
			$html                       .= '<li class="ironlatch-risk-row"><span class="ironlatch-pill' . $class . '">' . esc_html( $word ) . '</span><span class="ironlatch-risk-text"><strong>' . esc_html( $label ) . '</strong> ' . esc_html( self::reason( $row['area'], $row['reason'] ) ) . '</span><a href="' . esc_url( admin_url( 'admin.php?page=' . $slug ) ) . '">' . esc_html( $link ) . '</a></li>';
		}
		return $html . '</ul></section>';
	}
}
