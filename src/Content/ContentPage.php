<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Content;

defined( 'ABSPATH' ) || exit;

final class ContentPage {
	public function register(): void {
		$hook = add_submenu_page( 'amazing-security', __( 'Published content', 'amazingplugins-security-scanner' ), __( 'Content scan', 'amazingplugins-security-scanner' ), 'manage_options', 'amsec-content', array( $this, 'render' ) );
		add_action(
			'admin_enqueue_scripts',
			static function ( string $current ) use ( $hook ): void {
				if ( $current === $hook ) {
					wp_enqueue_style( 'amazing-security-admin', plugins_url( 'assets/admin.css', AMAZING_SECURITY_FILE ), array(), '0.1.0' );
				} }
		);
	}
	public function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'amazingplugins-security-scanner' ), '', array( 'response' => 403 ) );
		}
		try {
			$state = ( new WordPressContentService() )->create()->status();
		} catch ( \Throwable ) {
			$state = array( 'invalid' => true );
		}
		echo '<div class="wrap amazing-security-admin"><header class="amsec-header"><div><h1>' . esc_html__( 'Published content', 'amazingplugins-security-scanner' ) . '</h1><p>' . esc_html__( 'Review selected hidden-link and redirect patterns in public posts, pages and their approved comments.', 'amazingplugins-security-scanner' ) . '</p></div>';
		$active  = $state['active'] ?? null;
		$expired = is_array( $active ) && ! $active['finished'] && time() > $active['started_at'] + 86400;
		if ( empty( $state['invalid'] ) ) {
			$this->form( is_array( $active ) && ! $active['finished'] && ! $expired ? 'resume' : 'start', $active['scan_id'] ?? '' );
		}
		echo '</header><section class="amsec-overview"><h2>' . esc_html__( 'Coverage', 'amazingplugins-security-scanner' ) . '</h2><p>' . esc_html__( 'Published, non-password-protected posts/pages and approved native comments only. Private/draft content, custom post types, products/reviews, order/customer records and other database tables are excluded. Links are not contacted or checked against a reputation service. A match can be legitimate and needs review.', 'amazingplugins-security-scanner' ) . '</p><p>' . esc_html__( 'Each step processes up to 50 items, with a five-second work target. A run stops at 1,000 items, 16 MiB read or 30 seconds of work. Items over 128 KiB are skipped; at most 250 findings are retained. Slow database responses can take longer. Items added after a scan starts are checked on the next scan. Content can change while scanning, and later edits can be missed. No stored content is rendered here or changed.', 'amazingplugins-security-scanner' ) . '</p></section>';
		if ( ! empty( $state['invalid'] ) ) {
			echo '<div class="notice notice-error"><p>' . esc_html__( 'Scan state is unavailable or invalid. No coverage can be established. Ask the host administrator to review the local scan state before restarting.', 'amazingplugins-security-scanner' ) . '</p></div></div>';
			return;
		}
		if ( ! is_array( $active ) ) {
			echo '<section class="amsec-file-scan"><h2>' . esc_html__( 'No content scan yet', 'amazingplugins-security-scanner' ) . '</h2><p>' . esc_html__( 'Start a scan to review selected patterns. A scan with no findings does not establish that the site is malware-free.', 'amazingplugins-security-scanner' ) . '</p></section></div>';
			return;
		}
	 // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only administrator report pagination.
		$page = max( 1, min( 10, absint( $_GET['content_page'] ?? 1 ) ) );
		$this->report( $active, $page, $expired );
		foreach ( array(
			'previous' => __( 'Previous finished review', 'amazingplugins-security-scanner' ),
			'complete' => __( 'Last review without bounded-work gaps', 'amazingplugins-security-scanner' ),
		) as $key => $title ) {
			$old = $state[ $key ];
			if ( ! is_array( $old ) || $old['scan_id'] === $active['scan_id'] || ( 'complete' === $key && ( $state['previous']['scan_id'] ?? '' ) === $old['scan_id'] ) ) {
				continue;
			}
			echo '<details class="amsec-file-scan"><summary>' . esc_html( sprintf( /* translators: 1: title of an earlier review, 2: number of stored findings. */ __( '%1$s (%2$s stored findings)', 'amazingplugins-security-scanner' ), $title, (string) count( $old['findings'] ) ) ) . '</summary><p>' . esc_html__( 'These are earlier results, not a statement about current content. Showing up to five earlier findings.', 'amazingplugins-security-scanner' ) . '</p>';
			$this->table( array_slice( $old['findings'], 0, 5 ) );
			echo '</details>';
		}
		echo '</div>';
	}
	private function form( string $operation, string $id ): void {
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="amsec_content_scan"><input type="hidden" name="operation" value="' . esc_attr( $operation ) . '"><input type="hidden" name="scan_id" value="' . esc_attr( $id ) . '">';
		wp_nonce_field( 'start' === $operation ? 'amsec_content_start' : 'amsec_content_resume_' . $id );
		submit_button( 'start' === $operation ? __( 'Scan published content', 'amazingplugins-security-scanner' ) : __( 'Continue scan', 'amazingplugins-security-scanner' ), 'primary', 'submit', false );
		echo '</form>';
	}
	private function report( array $report, int $page, bool $expired ): void {
		$label = $expired ? __( 'Expired: incomplete review', 'amazingplugins-security-scanner' ) : ( $report['partial'] ? __( 'Partial coverage', 'amazingplugins-security-scanner' ) : ( $report['finished'] ? __( 'Selected pattern review finished', 'amazingplugins-security-scanner' ) : __( 'Review in progress', 'amazingplugins-security-scanner' ) ) );
		echo '<section class="amsec-file-scan"><div class="amsec-file-heading"><h2>' . esc_html__( 'Latest review', 'amazingplugins-security-scanner' ) . '</h2><span class="amsec-file-rule-age">' . esc_html( sprintf( /* translators: %s: version of the installed content rules. */ __( 'Installed content rules %s', 'amazingplugins-security-scanner' ), MarkupDetector::VERSION ) ) . '</span></div><div class="amsec-file-status" role="status"><strong>' . esc_html( $label ) . '</strong><span>' . esc_html( sprintf( /* translators: 1: number of processed items, 2: number of unknown items, 3: number of omitted findings. */ __( '%1$s items processed; %2$s unknown; %3$s findings omitted.', 'amazingplugins-security-scanner' ), (string) $report['processed'], (string) $report['unknown'], (string) $report['omitted'] ) ) . '</span></div><p>' . esc_html( sprintf( /* translators: %s: UTC date and time when the review started. */ __( 'Started UTC: %s. A completed review covers selected patterns and cannot certify the site as malware-free.', 'amazingplugins-security-scanner' ), gmdate( 'Y-m-d H:i:s', $report['started_at'] ) ) ) . '</p>';
		if ( $report['finished'] && '' !== $report['reason'] ) {
			echo '<p>' . esc_html__( 'Stop reason:', 'amazingplugins-security-scanner' ) . ' ' . esc_html(
				match ( $report['reason'] ) {
				'budget' => __( 'resource limit reached', 'amazingplugins-security-scanner' ),
				'database' => __( 'database unavailable', 'amazingplugins-security-scanner' ),
				'expired' => __( 'scan expired', 'amazingplugins-security-scanner' ),
				'context' => __( 'site address or rule version changed', 'amazingplugins-security-scanner' ),
				default => __( 'incomplete work', 'amazingplugins-security-scanner' ) }
			) . '.</p>';
		}
		$count = count( $report['findings'] );
		$pages = max( 1, (int) ceil( $count / 25 ) );
		$page  = min( $page, $pages );
		if ( 0 === $count ) {
			echo '<p>' . esc_html__( 'No selected review pattern has been recorded in this scan.', 'amazingplugins-security-scanner' ) . '</p>';
		} else {
			$this->table( array_slice( $report['findings'], ( $page - 1 ) * 25, 25 ) );
		}
		if ( $pages > 1 ) {
			echo '<nav aria-label="' . esc_attr__( 'Content finding pages', 'amazingplugins-security-scanner' ) . '">'; for ( $n = 1; $n <= $pages; ++$n ) {
					echo '<a class="button" href="' . esc_url(
						add_query_arg(
							array(
								'page'         => 'amsec-content',
								'content_page' => $n,
							),
							admin_url( 'admin.php' )
						)
					) . '"' . ( $n === $page ? ' aria-current="page"' : '' ) . '>' . esc_html( (string) $n ) . '</a> ';
			} echo '</nav>';
		}
		echo '</section>';
	}
	private function table( array $findings ): void {
		echo '<table class="widefat striped amsec-stacked-table"><thead><tr><th>' . esc_html__( 'Item', 'amazingplugins-security-scanner' ) . '</th><th>' . esc_html__( 'Pattern to review', 'amazingplugins-security-scanner' ) . '</th><th>' . esc_html__( 'Line', 'amazingplugins-security-scanner' ) . '</th><th>' . esc_html__( 'Review', 'amazingplugins-security-scanner' ) . '</th></tr></thead><tbody>';
		foreach ( $findings as $finding ) {
			$url      = $this->reviewUrl( $finding['kind'], $finding['id'] );
			$guidance = match ( $finding['rule'] ) {
				'AS-HTML-001' => __( 'Hidden external link: confirm why the link is present and hidden.', 'amazingplugins-security-scanner' ), 'AS-HTML-002' => __( 'External meta refresh: confirm the intended destination.', 'amazingplugins-security-scanner' ), 'AS-HTML-003' => __( 'Executable link scheme: review the action and its origin.', 'amazingplugins-security-scanner' ), 'AS-HTML-004' => __( 'Hidden external frame: confirm why the frame is present and hidden. A visible frame is not matched.', 'amazingplugins-security-scanner' ), 'AS-JS-001' => __( 'Literal external script redirect: confirm who added it.', 'amazingplugins-security-scanner' ), default => __( 'Review selected markup.', 'amazingplugins-security-scanner' ) };
			echo '<tr><td data-label="Item">' . esc_html( ucfirst( $finding['kind'] ) . ' #' . $finding['id'] ) . '</td><td data-label="Finding">' . esc_html( $guidance ) . '<br><small>' . esc_html( $finding['rule'] . ' / ' . $finding['version'] ) . '</small></td><td data-label="Line">' . esc_html( (string) $finding['line'] ) . '</td><td data-label="Review">';
			if ( '' !== $url ) {
				echo '<a href="' . esc_url( $url ) . '">' . esc_html__( 'Open editor', 'amazingplugins-security-scanner' ) . '</a>';
			} else {
					esc_html_e( 'Item changed or editor access unavailable', 'amazingplugins-security-scanner' );
			} echo '</td></tr>';
		}
		echo '</tbody></table>';
	}
	private function reviewUrl( string $kind, int $id ): string {
		$comment = 'comment' === $kind ? get_comment( $id ) : null;
		if ( 'comment' === $kind && ( ! $comment || '1' !== (string) $comment->comment_approved || ! in_array( $comment->comment_type, array( '', 'comment' ), true ) ) ) {
			return '';
		}
		$post = get_post( $comment ? $comment->comment_post_ID : $id );
		if ( ! $post || 'publish' !== $post->post_status || ! in_array( $post->post_type, array( 'post', 'page' ), true ) || '' !== $post->post_password || ! current_user_can( $comment ? 'edit_comment' : 'edit_post', $id ) ) {
			return '';
		}
		$url = $comment ? get_edit_comment_link( $id ) : get_edit_post_link( $id, 'raw' );
		return is_string( $url ) ? $url : '';
	}
}
