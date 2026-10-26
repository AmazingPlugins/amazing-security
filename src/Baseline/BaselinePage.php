<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Baseline;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Integrity\WordPressOptions;

final class BaselinePage {
	public function register(): void {
		add_submenu_page( 'amazing-security', __( 'Custom-code baselines', 'amazing-security-scanner' ), __( 'Code baselines', 'amazing-security-scanner' ), 'manage_options', 'amsec-baselines', array( $this, 'render' ) );
	}

	public function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'amazing-security-scanner' ), '', array( 'response' => 403 ) );
		}
		echo '<div class="wrap amazing-security-admin"><h1>' . esc_html__( 'Watch a plugin or theme', 'amazing-security-scanner' ) . '</h1><p>' . esc_html__( 'Pick an installed package, preview the file list, then approve it with your password. Later you can compare that reference with the files on disk. A reference is not proof the code was clean. WordPress.org checksums stay a separate check.', 'amazing-security-scanner' ) . '</p><details><summary>' . esc_html__( 'What the reference covers', 'amazing-security-scanner' ) . '</summary><p>' . esc_html__( 'PHP, PHTML, INC, JS, CSS, HTML, HTM, SVG, JSON and Twig. Up to 300 files. A mu-plugin or a plugin with one file covers that entry file. Linked, unreadable, or oversized files make the collection incomplete.', 'amazing-security-scanner' ) . '</p></details>';
		$repository = new BaselineRepository( new WordPressOptions() );
		try {
			list( , $state ) = $repository->snapshot();
			$targets         = ( new TargetResolver() )->targets();
		} catch ( \Throwable ) {
			echo '<p>' . esc_html__( 'Baseline storage or installed-package inventory is unavailable.', 'amazing-security-scanner' ) . '</p></div>';
			return;
		}
		if ( is_ssl() ) {
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="amsec_baseline"><input type="hidden" name="mode" value="preview"><label>' . esc_html__( 'Installed package', 'amazing-security-scanner' ) . ' <select name="target">';
			foreach ( $targets as $key => $target ) {
				echo '<option value="' . esc_attr( $key ) . '">' . esc_html( $key ) . '</option>';
			}
			echo '</select></label>';
			wp_nonce_field( 'amsec_baseline_preview' );
			submit_button( __( 'Prepare five-minute preview', 'amazing-security-scanner' ), 'secondary' );
			echo '</form>';
			$preview = $state['previews'][ (string) get_current_user_id() ] ?? null;
			if ( is_array( $preview ) && $preview['expires'] > time() ) {
				echo '<h2>' . esc_html__( 'Pending reference', 'amazing-security-scanner' ) . '</h2><p>' .
					/* translators: 1: package key; 2: number of covered files. */
					sprintf( esc_html__( '%1$s: %2$s covered files. Approval replaces any existing reference for this package after checking that the covered files and target are unchanged.', 'amazing-security-scanner' ), esc_html( $preview['key'] ), esc_html( (string) count( $preview['files'] ) ) ) . '</p><details><summary>' . esc_html__( 'Covered relative files and SHA-256 hashes', 'amazing-security-scanner' ) . '</summary><pre>' . esc_html( wp_json_encode( $preview['files'], JSON_PRETTY_PRINT ) ) . '</pre></details><form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="amsec_baseline"><input type="hidden" name="mode" value="approve"><input type="hidden" name="target" value="' . esc_attr( $preview['key'] ) . '"><input type="hidden" name="token" value="' . esc_attr( $preview['token'] ) . '">';
				wp_nonce_field( 'amsec_baseline_approve_' . $preview['token'] );
				echo '<p><label>' . esc_html__( 'Your password', 'amazing-security-scanner' ) . ' <input type="password" name="password" autocomplete="current-password" maxlength="1024" required></label></p><p><label><input type="checkbox" name="confirm" value="1" required> ' . esc_html__( 'I approve this reference and understand it replaces an existing baseline without establishing that the code is clean.', 'amazing-security-scanner' ) . '</label></p>';
				submit_button( __( 'Approve reference', 'amazing-security-scanner' ), 'secondary' );
				echo '</form>';
			}
		} else {
			echo '<p>' . esc_html__( 'Use HTTPS to prepare and approve a baseline.', 'amazing-security-scanner' ) . '</p>';
		}
		echo '<h2>' . esc_html__( 'Compare an approved package', 'amazing-security-scanner' ) . '</h2>';
		if ( array() === $state['baselines'] ) {
			echo '<p>' . esc_html__( 'There is no approved reference yet. Prepare one over HTTPS, then compare it here.', 'amazing-security-scanner' ) . '</p>';
		} else {
			echo '<form method="get"><input type="hidden" name="page" value="amsec-baselines"><label>' . esc_html__( 'Reference', 'amazing-security-scanner' ) . ' <select name="compare">';
			foreach ( $state['baselines'] as $key => $baseline ) {
				echo '<option value="' . esc_attr( $key ) . '">' . esc_html( $key ) . '</option>';
			}
			echo '</select></label>';
			wp_nonce_field( 'amsec_baseline_compare', '_wpnonce', false );
			submit_button( __( 'Compare covered files', 'amazing-security-scanner' ), 'secondary' );
			echo '</form>';
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Verified below before bounded read work.
		$key = is_string( $_GET['compare'] ?? null ) ? sanitize_text_field( wp_unslash( $_GET['compare'] ) ) : '';
		if ( '' !== $key ) {
			check_admin_referer( 'amsec_baseline_compare' );
			try {
				$changes = ( new BaselineService( $repository ) )->compare( ( new TargetResolver() )->resolve( $key ) );
				foreach ( $changes as $kind => $files ) {
					echo '<h3>' . sprintf(
						/* translators: 1: change kind, one of Added, Modified or Deleted; 2: number of files. */
						esc_html__( '%1$s: %2$s', 'amazing-security-scanner' ),
						esc_html(
							match ( $kind ) {
								'added' => __( 'Added', 'amazing-security-scanner' ),
								'modified' => __( 'Modified', 'amazing-security-scanner' ),
								'deleted' => __( 'Deleted', 'amazing-security-scanner' ),
								default => ucfirst( $kind ) }
						),
						esc_html( (string) count( $files ) )
					) . '</h3><pre>' . esc_html( implode( "\n", $files ) ) . '</pre>';
				}
				echo '<p>' . esc_html__( 'Comparison completed for the declared source assets. It does not establish malware status or cover excluded file types.', 'amazing-security-scanner' ) . '</p>';
			} catch ( \Throwable ) {
				echo '<p>' . esc_html__( 'Comparison unavailable or incomplete. No clean result or deleted-file conclusion is available.', 'amazing-security-scanner' ) . '</p>';
			}
		}
		echo '</div>';
	}
}
