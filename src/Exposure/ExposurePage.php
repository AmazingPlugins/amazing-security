<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Exposure;

defined( 'ABSPATH' ) || exit;

final class ExposurePage {
	public function register(): void {
		$hook = add_submenu_page( 'amazing-security', __( 'Local exposure inventory', 'amazing-security' ), __( 'Local inventory', 'amazing-security' ), 'manage_options', 'amsec-exposure', array( $this, 'render' ) );
		add_action(
			'admin_enqueue_scripts',
			static function ( string $current ) use ( $hook ): void {
				if ( $current === $hook ) {
					wp_enqueue_style( 'amazing-security-admin', plugins_url( 'assets/admin.css', AMAZING_SECURITY_FILE ), array(), '0.1.0' );
				}}
		);
	}
	public function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'amazing-security' ), '', array( 'response' => 403 ) );}
		$state = ( new WordPressExposureService() )->create()->status();
		echo '<div class="wrap amazing-security-admin"><header class="amsec-header"><div><h1>' . esc_html__( 'Local exposure inventory', 'amazing-security' ) . '</h1><p>' . esc_html__( 'Review selected filenames that may need a host access-policy check.', 'amazing-security' ) . '</p></div></header><section class="amsec-overview"><h2>' . esc_html__( 'Local evidence only', 'amazing-security' ) . '</h2><p>' . esc_html__( 'This inventory uses filenames and filesystem metadata. Candidate contents are not opened, read, executed or changed. No HTTP request is made to establish public reachability. A log, archive or backup-like filename can be legitimate; it does not prove sensitive contents, public exposure or a vulnerability.', 'amazing-security' ) . '</p><p>' . esc_html__( 'WordPress and content roots cover top-level entries only. Uploads descends at most three directory levels; plugin/theme/core subtrees and remote storage are outside this slice. Each fresh inventory stops at 1,500 entries, 50 directories, 100 candidates or a five-second work target. Slow filesystem calls may take longer. Limits, depth exclusions and unreadable/changing entries are partial or unknown. Repeating starts fresh; there is no resume cursor. Files and configured roots can change after capture, so stored paths are historical evidence.', 'amazing-security' ) . '</p></section>';
		if ( ! empty( $state['invalid'] ) ) {
			echo '<div class="notice notice-error"><p>' . esc_html__( 'Stored inventory state is invalid. No coverage can be established; ask the host administrator to review it.', 'amazing-security' ) . '</p></div></div>';
			return;}
		foreach ( array(
			'site'    => __( 'WordPress root: top level', 'amazing-security' ),
			'content' => __( 'Content root: top level', 'amazing-security' ),
			'uploads' => __( 'Local uploads: depth three', 'amazing-security' ),
		) as $alias => $label ) {
			echo '<section class="amsec-file-scan"><div class="amsec-file-heading"><h2>' . esc_html( $label ) . '</h2><form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="amsec_exposure_inventory"><input type="hidden" name="root" value="' . esc_attr( $alias ) . '">';
			wp_nonce_field( 'amsec_exposure_' . $alias );
			submit_button( __( 'Inventory this root', 'amazing-security' ), 'secondary', 'submit', false );
			echo '</form></div>';
			$report = $state['reports'][ $alias ] ?? null;
			if ( null === $report ) {
				echo '<p>' . esc_html__( 'No local inventory captured.', 'amazing-security' ) . '</p></section>';
					continue;}
			/* translators: 1: entry count; 2: directory count; 3: unknown item count; 4: excluded directory count. */
			echo '<div class="amsec-file-status"><strong>' . esc_html( $report['partial'] ? __( 'Partial or unknown inventory', 'amazing-security' ) : __( 'Selected local filename inventory finished', 'amazing-security' ) ) . '</strong><span>' . sprintf( esc_html__( '%1$s entries; %2$s directories; %3$s unknown; %4$s directories excluded.', 'amazing-security' ), esc_html( (string) $report['entries'] ), esc_html( (string) $report['directories'] ), esc_html( (string) $report['unknown'] ), esc_html( (string) $report['excluded'] ) ) . '</span></div><p>' .
			/* translators: %s: UTC timestamp when the local inventory was captured. */
			sprintf( esc_html__( 'Captured UTC: %s. No public reachability or contents verdict.', 'amazing-security' ), esc_html( gmdate( 'Y-m-d H:i:s', $report['captured_at'] ) ) ) . '</p>';
			foreach ( $report['reasons'] as $reason ) {
				echo '<p>' . esc_html(
					match ( $reason ) {
							'root_unavailable'=>__( 'Configured root unavailable, unsafe or unsupported.', 'amazing-security' ),
						'root_changed'=>__( 'Root metadata changed; candidates were discarded.', 'amazing-security' ),
						'entry_limit'=>__( 'Entry budget reached; later entries were not inventoried.', 'amazing-security' ),
						'directory_limit'=>__( 'Directory budget reached.', 'amazing-security' ),
						'candidate_limit'=>__( 'Candidate limit reached; later matches were not retained.', 'amazing-security' ),
						'depth_limit'=>__( 'Deeper uploads directories were excluded.', 'amazing-security' ),
						'work_target'=>__( 'Work target reached; inventory is incomplete.', 'amazing-security' ),
						default=>__( 'Some entries or directory metadata were unreadable, unsupported or changed.', 'amazing-security' )}
				) . '</p>';}
			if ( array() === $report['candidates'] ) {
				echo '<p>' . esc_html__( 'No selected candidate filename was retained. This is not a complete-site or exposure clearance.', 'amazing-security' ) . '</p>';
			} else {
				echo '<table class="widefat striped amsec-stacked-table"><thead><tr><th>' . esc_html__( 'Relative path', 'amazing-security' ) . '</th><th>' . esc_html__( 'Why review it', 'amazing-security' ) . '</th><th>' . esc_html__( 'Bytes', 'amazing-security' ) . '</th><th>' . esc_html__( 'Metadata UTC', 'amazing-security' ) . '</th></tr></thead><tbody>';
				foreach ( $report['candidates'] as $candidate ) {
					$why = match ( $candidate['category'] ) {
						'log'=>__( 'Selected debug/error log filename', 'amazing-security' ), 'database_dump'=>__( 'Database dump-like filename', 'amazing-security' ), 'configuration_leftover'=>__( 'Environment/configuration leftover-like filename', 'amazing-security' ), default=>__( 'Archive/backup-like filename', 'amazing-security' )};
						echo '<tr><td data-label="' . esc_attr__( 'Relative path', 'amazing-security' ) . '"><code>' . esc_html( $candidate['path'] ) . '</code></td><td data-label="' . esc_attr__( 'Review', 'amazing-security' ) . '">' . esc_html( $why ) . '</td><td data-label="' . esc_attr__( 'Bytes', 'amazing-security' ) . '">' . esc_html( (string) $candidate['bytes'] ) . '</td><td data-label="' . esc_attr__( 'Metadata UTC', 'amazing-security' ) . '">' . esc_html( gmdate( 'Y-m-d H:i:s', $candidate['modified_at'] ) ) . '</td></tr>';
				}echo '</tbody></table>';}
			echo '<p>' . esc_html__( 'Ask the host administrator to confirm whether the captured root maps to a served path and review access rules, retention and safe backup storage. There is no public download link or automatic deletion.', 'amazing-security' ) . '</p></section>';
		}
		echo '</div>';
	}
}
