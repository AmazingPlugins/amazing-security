<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

use AmazingPlugins\Security\Repair\WordPressPluginRepair;

final class RepairPage {
	public function register(): void {
		$hook = add_submenu_page( 'amazing-security', __( 'Review file repair', 'amazing-security' ), __( 'Review file repair', 'amazing-security' ), 'manage_options', 'amsec-repair', array( $this, 'render' ) );
		add_action(
			'admin_enqueue_scripts',
			static function ( string $currentHook ) use ( $hook ): void {
				if ( $hook === $currentHook ) {
					wp_enqueue_style( 'amazing-security-admin', plugins_url( 'assets/admin.css', AMAZING_SECURITY_FILE ), array(), '0.1.0' );
				}
			}
		);
	}

	public function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to review a file repair.', 'amazing-security' ), '', array( 'response' => 403 ) );
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only preview; POST actions carry their own nonces.
		$id = isset( $_GET['finding'] ) && is_string( $_GET['finding'] ) ? sanitize_text_field( wp_unslash( $_GET['finding'] ) ) : '';
		if ( ! preg_match( '/^[a-f0-9]{32}$/D', $id ) ) {
			echo '<div class="wrap amazing-security-admin"><h1>' . esc_html__( 'Review file repair', 'amazing-security' ) . '</h1>';
			echo '<p>' . esc_html__( 'There is no file waiting on this screen. A repair opens from one changed release file after an integrity scan.', 'amazing-security' ) . '</p>';
			echo '<p><a class="button" href="' . esc_url( admin_url( 'admin.php?page=amsec-file-checks#amsec-integrity' ) ) . '">' . esc_html__( 'Open integrity and file scan', 'amazing-security' ) . '</a></p></div>';
			return;
		}
		$repair  = new WordPressPluginRepair();
		$receipt = $repair->receipt( $id );
		echo '<div class="wrap amazing-security-admin"><h1>Review plugin file repair</h1><p><a href="' . esc_url( admin_url( 'admin.php?page=amsec-file-checks#amsec-integrity' ) ) . '">Back to integrity and file scan</a></p>';
		if ( null !== $receipt ) {
			if ( in_array( $receipt['status'], array( 'prepared', 'needs_recovery' ), true ) ) {
				echo '<div class="notice notice-error"><p>Replacement verification did not finish. The installed file may have changed. The private backup was retained. Inspect the current file and its SHA-256, then use WP-CLI recovery with that exact hash. Do not repeat the repair.</p><p><code>' . esc_html( 'wp amazing-security repair recover ' . $id . ' --current-sha256=<hash> --confirm' ) . '</code></p></div></div>';
				return;
			}
			if ( ! $repair->canRollback( $id ) ) {
				echo '<div class="notice notice-warning"><p>This file changed after the repair. The old backup cannot roll it back safely. Run a fresh integrity scan before reviewing another repair. You can then discard the old rollback backup.</p></div><form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="amsec_repair_retire"><input type="hidden" name="finding_id" value="' . esc_attr( $id ) . '"><input type="hidden" name="_wpnonce" value="' . esc_attr( wp_create_nonce( 'amsec_repair_retire_' . $id ) ) . '"><label><input type="checkbox" name="confirm" value="1" required> Discard the old backup after reviewing the new scan.</label><p><button class="button" type="submit">Discard old backup</button></p></form></div>';
				return;
			}
			echo '<p>The clean release file was installed. A private backup is available for rollback while the file still has the installed hash.</p><form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="amsec_repair_rollback"><input type="hidden" name="finding_id" value="' . esc_attr( $id ) . '"><input type="hidden" name="_wpnonce" value="' . esc_attr( wp_create_nonce( 'amsec_repair_rollback_' . $id ) ) . '"><button class="button" type="submit">Roll back this repair</button></form></div>';
			return;
		}
		$preview = $repair->preview( $id );
		if ( null === $preview ) {
			echo '<div class="notice notice-warning"><p>Repair is unavailable. The file, release identity, current hash, or trusted replacement could not be verified. Review the scan and try again after a fresh integrity check.</p></div></div>';
			return;
		}
		echo '<p>This replaces one changed file from an installed WordPress.org plugin. The current bytes must still match the scan. A private backup outside the site is required before replacement.</p><table class="widefat striped"><tbody>';
		foreach ( array(
			'Plugin'              => $preview->candidate->slug . ' ' . $preview->candidate->version,
			'File'                => $preview->candidate->relativePath,
			'Current SHA-256'     => $preview->candidate->observedSha256,
			'Replacement SHA-256' => $preview->replacement->sha256,
		) as $label => $value ) {
			echo '<tr><th scope="row">' . esc_html( $label ) . '</th><td><code>' . esc_html( $value ) . '</code></td></tr>';
		}
		echo '</tbody></table><p><a href="' . esc_url( $preview->replacement->sourceUrl ) . '" target="_blank" rel="noopener noreferrer">WordPress.org release archive</a></p>';
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="amsec_repair_apply"><input type="hidden" name="finding_id" value="' . esc_attr( $id ) . '"><input type="hidden" name="before_sha256" value="' . esc_attr( $preview->candidate->observedSha256 ) . '"><input type="hidden" name="after_sha256" value="' . esc_attr( $preview->replacement->sha256 ) . '"><input type="hidden" name="_wpnonce" value="' . esc_attr( wp_create_nonce( 'amsec_repair_apply_' . $id ) ) . '"><label><input type="checkbox" name="confirm" value="1" required> I reviewed this exact file and replacement hash.</label><p><button class="button button-primary" type="submit">Replace this file</button></p></form></div>';
	}
}
