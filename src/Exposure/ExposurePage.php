<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Exposure;

final class ExposurePage {
	public function register(): void {
		$hook = add_submenu_page( 'amazing-security', __( 'Local exposure inventory', 'amazing-security' ), __( 'Local inventory', 'amazing-security' ), 'manage_options', 'amsec-exposure', array( $this, 'render' ) );
		add_action(
			'admin_enqueue_scripts',
			static function ( string $current ) use ( $hook ): void {
				if ( $current === $hook ) {
					wp_enqueue_style( 'amazing-security-admin', plugins_url( 'assets/admin.css', AMAZING_SECURITY_FILE ), array(), AMAZING_SECURITY_VERSION );
				}}
		);
	}
	public function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'amazing-security' ), '', array( 'response' => 403 ) );}
		$state = ( new WordPressExposureService() )->create()->status();
		echo '<div class="wrap amazing-security-admin"><header class="amsec-header"><div><h1>Local exposure inventory</h1><p>Review selected filenames that may need a host access-policy check.</p></div></header><section class="amsec-overview"><h2>Local evidence only</h2><p>This inventory uses filenames and filesystem metadata. Candidate contents are not opened, read, executed or changed. No HTTP request is made to establish public reachability. A log, archive or backup-like filename can be legitimate; it does not prove sensitive contents, public exposure or a vulnerability.</p><p>WordPress and content roots cover top-level entries only. Uploads descends at most three directory levels; plugin/theme/core subtrees and remote storage are outside this slice. Each fresh inventory stops at 1,500 entries, 50 directories, 100 candidates or a five-second work target. Slow filesystem calls may take longer. Limits, depth exclusions and unreadable/changing entries are partial or unknown. Repeating starts fresh; there is no resume cursor. Files and configured roots can change after capture, so stored paths are historical evidence.</p></section>';
		if ( ! empty( $state['invalid'] ) ) {
			echo '<div class="notice inline notice-error"><p>Stored inventory state is invalid. No coverage can be established; ask the host administrator to review it.</p></div></div>';
			return;}
		foreach ( array(
			'site'    => 'WordPress root: top level',
			'content' => 'Content root: top level',
			'uploads' => 'Local uploads: depth three',
		) as $alias => $label ) {
			echo '<section class="amsec-file-scan"><div class="amsec-file-heading"><h2>' . esc_html( $label ) . '</h2><form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="amsec_exposure_inventory"><input type="hidden" name="root" value="' . esc_attr( $alias ) . '">';
			wp_nonce_field( 'amsec_exposure_' . $alias );
			submit_button( __( 'Inventory this root', 'amazing-security' ), 'secondary', 'submit', false );
			echo '</form></div>';
			$report = $state['reports'][ $alias ] ?? null;
			if ( null === $report ) {
				echo '<p>No local inventory captured.</p></section>';
					continue;}
			echo '<div class="amsec-file-status"><strong>' . esc_html( $report['partial'] ? 'Partial or unknown inventory' : 'Selected local filename inventory finished' ) . '</strong><span>' . esc_html( (string) $report['entries'] ) . ' entries; ' . esc_html( (string) $report['directories'] ) . ' directories; ' . esc_html( (string) $report['unknown'] ) . ' unknown; ' . esc_html( (string) $report['excluded'] ) . ' directories excluded.</span></div><p>Captured UTC: ' . esc_html( gmdate( 'Y-m-d H:i:s', $report['captured_at'] ) ) . '. No public reachability or contents verdict.</p>';
			foreach ( $report['reasons'] as $reason ) {
				echo '<p>' . esc_html(
					match ( $reason ) {
							'root_unavailable'=>'Configured root unavailable, unsafe or unsupported.',
						'root_changed'=>'Root metadata changed; candidates were discarded.',
						'entry_limit'=>'Entry budget reached; later entries were not inventoried.',
						'directory_limit'=>'Directory budget reached.',
						'candidate_limit'=>'Candidate limit reached; later matches were not retained.',
						'depth_limit'=>'Deeper uploads directories were excluded.',
						'work_target'=>'Work target reached; inventory is incomplete.',
						default=>'Some entries or directory metadata were unreadable, unsupported or changed.'}
				) . '</p>';}
			if ( array() === $report['candidates'] ) {
				echo '<p>No selected candidate filename was retained. This is not a complete-site or exposure clearance.</p>';
			} else {
				echo '<table class="widefat striped amsec-stacked-table"><thead><tr><th>Relative path</th><th>Why review it</th><th>Bytes</th><th>Metadata UTC</th></tr></thead><tbody>';
				foreach ( $report['candidates'] as $candidate ) {
					$why = match ( $candidate['category'] ) {
						'log'=>'Selected debug/error log filename', 'database_dump'=>'Database dump-like filename', 'configuration_leftover'=>'Environment/configuration leftover-like filename', default=>'Archive/backup-like filename'};
						echo '<tr><td data-label="Relative path"><code>' . esc_html( $candidate['path'] ) . '</code></td><td data-label="Review">' . esc_html( $why ) . '</td><td data-label="Bytes">' . esc_html( (string) $candidate['bytes'] ) . '</td><td data-label="Metadata UTC">' . esc_html( gmdate( 'Y-m-d H:i:s', $candidate['modified_at'] ) ) . '</td></tr>';
				}echo '</tbody></table>';}
			echo '<p>Ask the host administrator to confirm whether the captured root maps to a served path and review access rules, retention and safe backup storage. There is no public download link or automatic deletion.</p></section>';
		}
		echo '</div>';
	}
}
