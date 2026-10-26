<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Exposure;

defined( 'ABSPATH' ) || exit;

final class ExposurePage {
	public function register(): void {
		$hook = add_submenu_page( 'amazing-security', __( 'Local exposure inventory', 'amazingplugins-security-scanner' ), __( 'Local inventory', 'amazingplugins-security-scanner' ), 'manage_options', 'amsec-exposure', array( $this, 'render' ) );
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
			wp_die( esc_html__( 'Administrator access required.', 'amazingplugins-security-scanner' ), '', array( 'response' => 403 ) );}
		$state = ( new WordPressExposureService() )->create()->status();
		echo '<div class="wrap amazing-security-admin"><header class="amsec-header"><div><h1>' . esc_html__( 'Local exposure inventory', 'amazingplugins-security-scanner' ) . '</h1><p>' . esc_html__( 'Review selected filenames that may need a host access-policy check.', 'amazingplugins-security-scanner' ) . '</p></div></header><section class="amsec-overview"><h2>' . esc_html__( 'Local evidence only', 'amazingplugins-security-scanner' ) . '</h2><p>' . esc_html__( 'This inventory uses filenames and filesystem metadata. Candidate contents are not opened, read, executed or changed. No HTTP request is made to establish public reachability. A log, archive or backup-like filename can be legitimate; it does not prove sensitive contents, public exposure or a vulnerability.', 'amazingplugins-security-scanner' ) . '</p><p>' . esc_html__( 'WordPress and content roots cover top-level entries only. Uploads descends at most three directory levels; plugin/theme/core subtrees and remote storage are outside this slice. Each fresh inventory stops at 1,500 entries, 50 directories, 100 candidates or a five-second work target. Slow filesystem calls may take longer. Limits, depth exclusions and unreadable/changing entries are partial or unknown. Repeating starts fresh; there is no resume cursor. Files and configured roots can change after capture, so stored paths are historical evidence.', 'amazingplugins-security-scanner' ) . '</p></section>';
		if ( ! empty( $state['invalid'] ) ) {
			echo '<div class="notice notice-error"><p>' . esc_html__( 'Stored inventory state is invalid. No coverage can be established; ask the host administrator to review it.', 'amazingplugins-security-scanner' ) . '</p></div></div>';
			return;}
		foreach ( array(
			'site'    => __( 'WordPress root: top level', 'amazingplugins-security-scanner' ),
			'content' => __( 'Content root: top level', 'amazingplugins-security-scanner' ),
			'uploads' => __( 'Local uploads: depth three', 'amazingplugins-security-scanner' ),
		) as $alias => $label ) {
			echo '<section class="amsec-file-scan"><div class="amsec-file-heading"><h2>' . esc_html( $label ) . '</h2><form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="amsec_exposure_inventory"><input type="hidden" name="root" value="' . esc_attr( $alias ) . '">';
			wp_nonce_field( 'amsec_exposure_' . $alias );
			submit_button( __( 'Inventory this root', 'amazingplugins-security-scanner' ), 'secondary', 'submit', false );
			echo '</form></div>';
			$report = $state['reports'][ $alias ] ?? null;
			if ( null === $report ) {
				echo '<p>' . esc_html__( 'No local inventory captured.', 'amazingplugins-security-scanner' ) . '</p></section>';
					continue;}
			/* translators: 1: entry count; 2: directory count; 3: unknown item count; 4: excluded directory count. */
			echo '<div class="amsec-file-status"><strong>' . esc_html( $report['partial'] ? __( 'Partial or unknown inventory', 'amazingplugins-security-scanner' ) : __( 'Selected local filename inventory finished', 'amazingplugins-security-scanner' ) ) . '</strong><span>' . sprintf( /* translators: 1: entries seen, 2: directories read, 3: unknown entries, 4: directories skipped. */ esc_html__( 'Entries: %1$s. Directories: %2$s. Unknown: %3$s. Directories skipped: %4$s.', 'amazingplugins-security-scanner' ), esc_html( (string) $report['entries'] ), esc_html( (string) $report['directories'] ), esc_html( (string) $report['unknown'] ), esc_html( (string) $report['excluded'] ) ) . '</span></div><p>' .
			/* translators: %s: UTC timestamp when the local inventory was captured. */
			sprintf( esc_html__( 'Captured UTC: %s. No public reachability or contents verdict.', 'amazingplugins-security-scanner' ), esc_html( gmdate( 'Y-m-d H:i:s', $report['captured_at'] ) ) ) . '</p>';
			foreach ( $report['reasons'] as $reason ) {
				echo '<p>' . esc_html(
					match ( $reason ) {
							'root_unavailable'=>__( 'Configured root unavailable, unsafe or unsupported.', 'amazingplugins-security-scanner' ),
						'root_changed'=>__( 'Root metadata changed; candidates were discarded.', 'amazingplugins-security-scanner' ),
						'entry_limit'=>__( 'Entry budget reached; later entries were not inventoried.', 'amazingplugins-security-scanner' ),
						'directory_limit'=>__( 'Directory budget reached.', 'amazingplugins-security-scanner' ),
						'candidate_limit'=>__( 'Candidate limit reached; later matches were not retained.', 'amazingplugins-security-scanner' ),
						'depth_limit'=>__( 'Deeper uploads directories were excluded.', 'amazingplugins-security-scanner' ),
						'work_target'=>__( 'Work target reached; inventory is incomplete.', 'amazingplugins-security-scanner' ),
						default=>__( 'Some entries or directory metadata were unreadable, unsupported or changed.', 'amazingplugins-security-scanner' )}
				) . '</p>';}
			if ( array() === $report['candidates'] ) {
				echo '<p>' . esc_html__( 'No selected candidate filename was retained. This is not a complete-site or exposure clearance.', 'amazingplugins-security-scanner' ) . '</p>';
			} else {
				echo '<table class="widefat striped amsec-stacked-table"><thead><tr><th>' . esc_html__( 'Relative path', 'amazingplugins-security-scanner' ) . '</th><th>' . esc_html__( 'Why review it', 'amazingplugins-security-scanner' ) . '</th><th>' . esc_html__( 'Bytes', 'amazingplugins-security-scanner' ) . '</th><th>' . esc_html__( 'Metadata UTC', 'amazingplugins-security-scanner' ) . '</th></tr></thead><tbody>';
				foreach ( $report['candidates'] as $candidate ) {
					$why = match ( $candidate['category'] ) {
						'log'=>__( 'Selected debug/error log filename', 'amazingplugins-security-scanner' ), 'database_dump'=>__( 'Database dump-like filename', 'amazingplugins-security-scanner' ), 'configuration_leftover'=>__( 'Environment/configuration leftover-like filename', 'amazingplugins-security-scanner' ), default=>__( 'Archive/backup-like filename', 'amazingplugins-security-scanner' )};
						echo '<tr><td data-label="' . esc_attr__( 'Relative path', 'amazingplugins-security-scanner' ) . '"><code>' . esc_html( $candidate['path'] ) . '</code></td><td data-label="' . esc_attr__( 'Review', 'amazingplugins-security-scanner' ) . '">' . esc_html( $why ) . '</td><td data-label="' . esc_attr__( 'Bytes', 'amazingplugins-security-scanner' ) . '">' . esc_html( (string) $candidate['bytes'] ) . '</td><td data-label="' . esc_attr__( 'Metadata UTC', 'amazingplugins-security-scanner' ) . '">' . esc_html( gmdate( 'Y-m-d H:i:s', $candidate['modified_at'] ) ) . '</td></tr>';
				}echo '</tbody></table>';}
			echo '</section>';
		}
		echo '<p>' . esc_html__( 'Ask the host administrator to confirm whether the captured root maps to a served path and review access rules, retention and safe backup storage. There is no public download link or automatic deletion.', 'amazingplugins-security-scanner' ) . '</p></div>';
	}
}
