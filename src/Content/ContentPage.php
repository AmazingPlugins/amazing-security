<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Content;

final class ContentPage {
	public function register(): void {
		$hook = add_submenu_page( 'amazing-security', 'Published content', 'Content scan', 'manage_options', 'amsec-content', array( $this, 'render' ) );
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
			wp_die( esc_html__( 'Administrator access required.', 'amazing-security' ), '', array( 'response' => 403 ) );
		}
		try {
			$state = ( new WordPressContentService() )->create()->status();
		} catch ( \Throwable ) {
			$state = array( 'invalid' => true );
		}
		echo '<div class="wrap amazing-security-admin"><header class="amsec-header"><div><h1>Published content</h1><p>Review selected hidden-link and redirect patterns in public posts, pages and their approved comments.</p></div>';
		$active  = $state['active'] ?? null;
		$expired = is_array( $active ) && ! $active['finished'] && time() > $active['started_at'] + 86400;
		if ( empty( $state['invalid'] ) ) {
			$this->form( is_array( $active ) && ! $active['finished'] && ! $expired ? 'resume' : 'start', $active['scan_id'] ?? '' );
		}
		echo '</header><section class="amsec-overview"><h2>Coverage</h2><p>Published, non-password-protected posts/pages and approved native comments only. Private/draft content, custom post types, products/reviews, order/customer records and other database tables are excluded. Links are not contacted or checked against a reputation service. A match can be legitimate and needs review.</p><p>Each step processes up to 50 items, with a five-second work target. A run stops at 1,000 items, 16 MiB read or 30 seconds of work. Items over 128 KiB are skipped; at most 250 findings are retained. Slow database responses can take longer. Items added after a scan starts are checked on the next scan. Content can change while scanning, and later edits can be missed. No stored content is rendered here or changed.</p></section>';
		if ( ! empty( $state['invalid'] ) ) {
			echo '<div class="notice notice-error"><p>Scan state is unavailable or invalid. No coverage can be established. Ask the host administrator to review the local scan state before restarting.</p></div></div>';
			return;
		}
		if ( ! is_array( $active ) ) {
			echo '<section class="amsec-file-scan"><h2>No content scan yet</h2><p>Start a scan to review selected patterns. A scan with no findings does not establish that the site is malware-free.</p></section></div>';
			return;
		}
	 // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only administrator report pagination.
		$page = max( 1, min( 10, absint( $_GET['content_page'] ?? 1 ) ) );
		$this->report( $active, $page, $expired );
		foreach ( array(
			'previous' => 'Previous finished review',
			'complete' => 'Last review without bounded-work gaps',
		) as $key => $title ) {
			$old = $state[ $key ];
			if ( ! is_array( $old ) || $old['scan_id'] === $active['scan_id'] || ( 'complete' === $key && ( $state['previous']['scan_id'] ?? '' ) === $old['scan_id'] ) ) {
				continue;
			}
			echo '<details class="amsec-file-scan"><summary>' . esc_html( $title ) . ' (' . esc_html( (string) count( $old['findings'] ) ) . ' stored findings)</summary><p>These are earlier results, not a statement about current content. Showing up to five earlier findings.</p>';
			$this->table( array_slice( $old['findings'], 0, 5 ) );
			echo '</details>';
		}
		echo '</div>';
	}
	private function form( string $operation, string $id ): void {
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="amsec_content_scan"><input type="hidden" name="operation" value="' . esc_attr( $operation ) . '"><input type="hidden" name="scan_id" value="' . esc_attr( $id ) . '">';
		wp_nonce_field( 'start' === $operation ? 'amsec_content_start' : 'amsec_content_resume_' . $id );
		submit_button( 'start' === $operation ? 'Scan published content' : 'Continue scan', 'primary', 'submit', false );
		echo '</form>';
	}
	private function report( array $report, int $page, bool $expired ): void {
		$label = $expired ? 'Expired: incomplete review' : ( $report['partial'] ? 'Partial coverage' : ( $report['finished'] ? 'Selected pattern review finished' : 'Review in progress' ) );
		echo '<section class="amsec-file-scan"><div class="amsec-file-heading"><h2>Latest review</h2><span class="amsec-file-rule-age">Installed content rules ' . esc_html( MarkupDetector::VERSION ) . '</span></div><div class="amsec-file-status" role="status"><strong>' . esc_html( $label ) . '</strong><span>' . esc_html( (string) $report['processed'] ) . ' items processed; ' . esc_html( (string) $report['unknown'] ) . ' unknown; ' . esc_html( (string) $report['omitted'] ) . ' findings omitted.</span></div><p>Started UTC: ' . esc_html( gmdate( 'Y-m-d H:i:s', $report['started_at'] ) ) . '. A completed review covers selected patterns and cannot certify the site as malware-free.</p>';
		if ( $report['finished'] && '' !== $report['reason'] ) {
			echo '<p>Stop reason: ' . esc_html(
				match ( $report['reason'] ) {
				'budget' => 'resource limit reached',
				'database' => 'database unavailable',
				'expired' => 'scan expired',
				'context' => 'site address or rule version changed',
				default => 'incomplete work' }
			) . '.</p>';
		}
		$count = count( $report['findings'] );
		$pages = max( 1, (int) ceil( $count / 25 ) );
		$page  = min( $page, $pages );
		if ( 0 === $count ) {
			echo '<p>No selected review pattern has been recorded in this scan.</p>';
		} else {
			$this->table( array_slice( $report['findings'], ( $page - 1 ) * 25, 25 ) );
		}
		if ( $pages > 1 ) {
			echo '<nav aria-label="Content finding pages">'; for ( $n = 1; $n <= $pages; ++$n ) {
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
		echo '<table class="widefat striped amsec-stacked-table"><thead><tr><th>Item</th><th>Pattern to review</th><th>Line</th><th>Review</th></tr></thead><tbody>';
		foreach ( $findings as $finding ) {
			$url      = $this->reviewUrl( $finding['kind'], $finding['id'] );
			$guidance = match ( $finding['rule'] ) {
				'AS-HTML-001' => 'Hidden external link: confirm why the link is present and hidden.', 'AS-HTML-002' => 'External meta refresh: confirm the intended destination.', 'AS-HTML-003' => 'Executable link scheme: review the action and its origin.', 'AS-JS-001' => 'Literal external script redirect: confirm who added it.', default => 'Review selected markup.' };
			echo '<tr><td data-label="Item">' . esc_html( ucfirst( $finding['kind'] ) . ' #' . $finding['id'] ) . '</td><td data-label="Finding">' . esc_html( $guidance ) . '<br><small>' . esc_html( $finding['rule'] . ' / ' . $finding['version'] ) . '</small></td><td data-label="Line">' . esc_html( (string) $finding['line'] ) . '</td><td data-label="Review">';
			if ( '' !== $url ) {
				echo '<a href="' . esc_url( $url ) . '">Open editor</a>';
			} else {
					echo 'Item changed or editor access unavailable';
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
