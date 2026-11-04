<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Fixes\FixProposal;
use AmazingPlugins\Security\Fixes\WordPressFixRepository;
use AmazingPlugins\Security\Integrity\WordPressOptions;
use AmazingPlugins\Security\Mcp\McpPreferences;
use Throwable;

final class FixReviewPage {
	public function register(): void {
		add_submenu_page( 'ironlatch-security-scanner', __( 'Review security change', 'ironlatch-security-scanner' ), __( 'Review security change', 'ironlatch-security-scanner' ), 'manage_options', 'ironlatch-fix-review', array( $this, 'render' ) );
	}

	public function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You cannot review this change.', 'ironlatch-security-scanner' ), '', array( 'response' => 403 ) );
		}
		// This is a read-only page; the identifier selects one stored proposal.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$id = isset( $_GET['proposal'] ) && is_string( $_GET['proposal'] ) ? sanitize_text_field( wp_unslash( $_GET['proposal'] ) ) : '';
		if ( ! preg_match( '/^[a-f0-9]{32}$/D', $id ) ) {
			echo '<div class="wrap ironlatch-security-scanner-admin"><h1>' . esc_html__( 'Review security change', 'ironlatch-security-scanner' ) . '</h1><p>' . esc_html__( 'There is no saved proposal on this screen. One appears here after a scan offers a single setting change.', 'ironlatch-security-scanner' ) . '</p><p><a class="button" href="' . esc_url( admin_url( 'admin.php?page=ironlatch-recommendations' ) ) . '">' . esc_html__( 'Open recommendations', 'ironlatch-security-scanner' ) . '</a></p></div>';
			return;
		}
		try {
			$proposal = ( new WordPressFixRepository( $GLOBALS['wpdb'] ) )->get( $id );
		} catch ( Throwable ) {
			$proposal = null;
		}
		if ( null === $proposal ) {
			echo '<div class="wrap ironlatch-security-scanner-admin"><h1>' . esc_html__( 'Review security change', 'ironlatch-security-scanner' ) . '</h1><p>' . esc_html__( 'Proposal not found.', 'ironlatch-security-scanner' ) . '</p></div>';
			return;
		}
		$enabled = ( new McpPreferences( new WordPressOptions() ) )->enabled();
		$nonce   = wp_create_nonce( 'ironlatch_fix_approve_' . $id );
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only notice after a completed POST redirect.
		$verification = isset( $_GET['verification'] ) && is_string( $_GET['verification'] ) && 'pending' === sanitize_key( wp_unslash( $_GET['verification'] ) ) ? 'pending' : '';
		$liveMode     = get_option( 'ironlatch_login_rate_mode', 'off' );
		// html() escapes every dynamic field while preserving form markup.
		echo wp_kses( $this->html( $proposal, $nonce, admin_url( 'admin-post.php' ), is_ssl(), $enabled, time(), wp_create_nonce( 'ironlatch_fix_rollback_' . $id ), $verification, is_string( $liveMode ) ? $liveMode : '' ), AdminHtml::allowed() );
	}

	public function html( FixProposal $proposal, string $nonce, string $actionUrl, bool $secure, bool $enabled, int $now, string $rollbackNonce = '', string $verification = '', ?string $liveMode = null ): string {
		$labels  = array(
			'off'     => __( 'Off', 'ironlatch-security-scanner' ),
			'observe' => __( 'Observe only', 'ironlatch-security-scanner' ),
			'block'   => __( 'Block repeated failures', 'ironlatch-security-scanner' ),
		);
		$before  = $labels[ $proposal->beforeMode ];
		$after   = $labels[ $proposal->afterMode ];
		$html    = '<div class="wrap ironlatch-security-scanner-admin"><section class="ironlatch-fix-review" aria-labelledby="ironlatch-fix-title"><h1 id="ironlatch-fix-title">' . esc_html__( 'Review security change', 'ironlatch-security-scanner' ) . '</h1><p>' . esc_html__( 'Ironlatch Security Scanner will change one setting on this site. Review it here before anything is applied.', 'ironlatch-security-scanner' ) . '</p>';
		$applied = 'applied' === $proposal->status;
		$current = null === $liveMode ? $proposal->beforeMode : $liveMode;
		$stale   = 'pending' === $proposal->status && $current !== $proposal->beforeMode;
		$html   .= '<dl class="ironlatch-fix-diff"><div><dt>' . esc_html__( 'Setting', 'ironlatch-security-scanner' ) . '</dt><dd>' . esc_html__( 'Login attempt response', 'ironlatch-security-scanner' ) . '</dd></div><div><dt>' . ( $applied ? esc_html__( 'Previous', 'ironlatch-security-scanner' ) : esc_html__( 'Current', 'ironlatch-security-scanner' ) ) . '</dt><dd>' . esc_html( $applied ? $before : ( $labels[ $current ] ?? esc_html__( 'Unknown', 'ironlatch-security-scanner' ) ) ) . '</dd></div><div><dt>' . ( $applied ? esc_html__( 'Applied', 'ironlatch-security-scanner' ) : esc_html__( 'Proposed', 'ironlatch-security-scanner' ) ) . '</dt><dd>' . esc_html( $after ) . '</dd></div></dl>';
		$html   .= '<p>' . esc_html__( 'This proposal expires at', 'ironlatch-security-scanner' ) . ' <time datetime="' . esc_attr( gmdate( 'c', $proposal->expiresAt ) ) . '">' . esc_html( gmdate( 'Y-m-d H:i:s T', $proposal->expiresAt ) ) . '</time>.</p>';
		if ( 'block' === $proposal->afterMode ) {
			$html .= '<p class="notice notice-warning inline">' . sprintf(
				/* translators: %s: WP-CLI command that turns off login blocking. */
				esc_html__( 'Blocking can affect people who share an address. If you cannot sign in, run %s through WP-CLI.', 'ironlatch-security-scanner' ),
				'<code>wp ironlatch-security-scanner login disable</code>'
			) . '</p>';
		}
		if ( 'pending' === $verification && 'applied' === $proposal->status ) {
			$html .= '<p role="status">' . esc_html__( 'The change was applied but could not be verified. Run a new hardening scan.', 'ironlatch-security-scanner' ) . '</p>';
		}
		if ( $stale ) {
			$html .= '<p role="status">' . esc_html__( 'The setting changed since this proposal was created. Run a new scan and request a new proposal.', 'ironlatch-security-scanner' ) . '</p>';
		}
		if ( 'applied' === $proposal->status && $proposal->canRollback( $now ) ) {
			$html .= '<p role="status">' . esc_html__( 'This change was applied. You can restore the previous mode for 24 hours.', 'ironlatch-security-scanner' ) . '</p><form method="post" action="' . esc_url( $actionUrl ) . '"><input type="hidden" name="action" value="ironlatch_fix_rollback"><input type="hidden" name="proposal_id" value="' . esc_attr( $proposal->id ) . '"><input type="hidden" name="_wpnonce" value="' . esc_attr( $rollbackNonce ) . '"><input type="hidden" name="confirm" value="1"><button type="submit" class="button">' . esc_html__( 'Restore previous mode', 'ironlatch-security-scanner' ) . '</button></form>';
		} elseif ( ! $enabled ) {
			$html .= '<p role="status">' . esc_html__( 'AI assistant access is off. This proposal cannot be approved.', 'ironlatch-security-scanner' ) . '</p>';
		} elseif ( 'pending' === $proposal->status && ! $stale && ! $proposal->isExpired( $now ) && ( 'block' !== $proposal->afterMode || $secure ) ) {
			$html .= '<form method="post" action="' . esc_url( $actionUrl ) . '"><input type="hidden" name="action" value="ironlatch_fix_approve"><input type="hidden" name="proposal_id" value="' . esc_attr( $proposal->id ) . '"><input type="hidden" name="_wpnonce" value="' . esc_attr( $nonce ) . '"><input type="hidden" name="confirm" value="1">';
			if ( 'block' === $proposal->afterMode ) {
				$html .= '<label for="ironlatch-fix-password">' . esc_html__( 'Current WordPress password', 'ironlatch-security-scanner' ) . '</label><input id="ironlatch-fix-password" type="password" name="password" autocomplete="current-password" required>';
			}
			$html .= '<button type="submit" class="button button-primary">' . esc_html__( 'Approve this change', 'ironlatch-security-scanner' ) . '</button></form>';
		} elseif ( 'block' === $proposal->afterMode && ! $secure && 'pending' === $proposal->status ) {
			$html .= '<p role="status">' . esc_html__( 'HTTPS is required before this change can be approved.', 'ironlatch-security-scanner' ) . '</p>';
		} else {
			$html .= '<p role="status">' . sprintf(
				/* translators: %s: status of the proposal, such as expired or applied. */
				esc_html__( 'This proposal is %s. No change can be approved here.', 'ironlatch-security-scanner' ),
				esc_html( $proposal->isExpired( $now ) && 'pending' === $proposal->status ? __( 'expired', 'ironlatch-security-scanner' ) : str_replace( '_', ' ', $proposal->status ) )
			) . '</p>';
		}
		return $html . '</section></div>';
	}
}
