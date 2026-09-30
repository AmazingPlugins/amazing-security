<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Baseline;

use AmazingPlugins\Security\Integrity\WordPressOptions;

final class BaselinePage {
	public function register(): void {
		add_submenu_page( 'amazing-security', 'Custom-code baselines', 'Code baselines', 'manage_options', 'amsec-baselines', array( $this, 'render' ) );
	}

	public function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'amazing-security' ), '', array( 'response' => 403 ) );
		}
		echo '<div class="wrap"><h1>Owner-approved code baselines</h1><p>A baseline is your reference for later changes. It does not prove that code is clean, authentic or malware-free. Official checksum checks remain separate. Only declared source assets in the selected package are covered; mu-plugins and standalone plugins cover the selected entry file only.</p><p>Coverage: PHP, PHTML, INC, JS, CSS, HTML, HTM, SVG, JSON and Twig. Limit: 300 files, 1,500 traversed entries, 2 MiB per source file, 16 MiB source bytes (read twice for verification) and five seconds per collection. Linked, unreadable or oversized entries make collection incomplete. Collection rechecks file hashes, metadata and directory listings, but cannot freeze the filesystem. At most ten baselines and ten pending previews share a 512 KiB storage budget.</p>';
		$repository = new BaselineRepository( new WordPressOptions() );
		try {
			list( , $state ) = $repository->snapshot();
			$targets         = ( new TargetResolver() )->targets();
		} catch ( \Throwable ) {
			echo '<p>Baseline storage or installed-package inventory is unavailable.</p></div>';
			return;
		}
		if ( is_ssl() ) {
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="amsec_baseline"><input type="hidden" name="mode" value="preview"><label>Installed package <select name="target">';
			foreach ( $targets as $key => $target ) {
				echo '<option value="' . esc_attr( $key ) . '">' . esc_html( $key ) . '</option>';
			}
			echo '</select></label>';
			wp_nonce_field( 'amsec_baseline_preview' );
			submit_button( 'Prepare five-minute preview', 'secondary' );
			echo '</form>';
			$preview = $state['previews'][ (string) get_current_user_id() ] ?? null;
			if ( is_array( $preview ) && $preview['expires'] > time() ) {
				echo '<h2>Pending reference</h2><p>' . esc_html( $preview['key'] ) . ': ' . esc_html( (string) count( $preview['files'] ) ) . ' covered files. Approval replaces any existing reference for this package after checking that the covered files and target are unchanged.</p><details><summary>Covered relative files and SHA-256 hashes</summary><pre>' . esc_html( wp_json_encode( $preview['files'], JSON_PRETTY_PRINT ) ) . '</pre></details><form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="amsec_baseline"><input type="hidden" name="mode" value="approve"><input type="hidden" name="target" value="' . esc_attr( $preview['key'] ) . '"><input type="hidden" name="token" value="' . esc_attr( $preview['token'] ) . '">';
				wp_nonce_field( 'amsec_baseline_approve_' . $preview['token'] );
				echo '<p><label>Your password <input type="password" name="password" autocomplete="current-password" maxlength="1024" required></label></p><p><label><input type="checkbox" name="confirm" value="1" required> I approve this reference and understand it replaces an existing baseline without establishing that the code is clean.</label></p>';
				submit_button( 'Approve reference', 'secondary' );
				echo '</form>';
			}
		} else {
			echo '<p>Use HTTPS to prepare and approve a baseline.</p>';
		}
		echo '<h2>Compare an approved package</h2><form method="get"><input type="hidden" name="page" value="amsec-baselines"><label>Reference <select name="compare">';
		foreach ( $state['baselines'] as $key => $baseline ) {
			echo '<option value="' . esc_attr( $key ) . '">' . esc_html( $key ) . '</option>';
		}
		echo '</select></label>';
		wp_nonce_field( 'amsec_baseline_compare', '_wpnonce', false );
		submit_button( 'Compare covered files', 'secondary' );
		echo '</form>';
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Verified below before bounded read work.
		$key = is_string( $_GET['compare'] ?? null ) ? sanitize_text_field( wp_unslash( $_GET['compare'] ) ) : '';
		if ( '' !== $key ) {
			check_admin_referer( 'amsec_baseline_compare' );
			try {
				$changes = ( new BaselineService( $repository ) )->compare( ( new TargetResolver() )->resolve( $key ) );
				foreach ( $changes as $kind => $files ) {
					echo '<h3>' . esc_html( ucfirst( $kind ) ) . ': ' . esc_html( (string) count( $files ) ) . '</h3><pre>' . esc_html( implode( "\n", $files ) ) . '</pre>';
				}
				echo '<p>Comparison completed for the declared source assets. It does not establish malware status or cover excluded file types.</p>';
			} catch ( \Throwable ) {
				echo '<p>Comparison unavailable or incomplete. No clean result or deleted-file conclusion is available.</p>';
			}
		}
		echo '</div>';
	}
}
