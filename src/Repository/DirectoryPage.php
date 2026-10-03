<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Repository;

final class DirectoryPage {
	public function register(): void {
		$hook = add_submenu_page( 'amazing-security', __( 'Plugin directory status', 'amazing-security' ), __( 'Directory status', 'amazing-security' ), 'manage_options', 'amsec-repository', array( $this, 'render' ) );
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
		$state = ( new WordPressDirectoryService() )->create()->status();
		$now   = time();
		echo '<div class="wrap amazing-security-admin"><header class="amsec-header"><div><h1>Plugin directory status</h1><p>Optional WordPress.org directory observations for selected installed plugin candidates.</p></div></header><section class="amsec-overview"><h2>Scope and privacy</h2><p>Each consented lookup sends one directory slug to WordPress.org, which sees your server IP. It does not send the installed version, site URL, credentials or contents. No lookup runs automatically. Up to 100 standard plugin entries are listed; custom-update, standalone and symlink packages are unsupported.</p><p>A directory slug match does not authenticate installed code. Closure is a directory observation, not a malware verdict. Missing records and old updates do not prove abandonment or a vulnerability. No plugin is deactivated or changed. Results older than 24 hours, or for a changed installation, are historical. A repeated lookup within ten minutes uses its saved result.</p></section>';
		if ( ! empty( $state['invalid'] ) ) {
			echo '<div class="notice notice-error"><p>Stored advisory state is invalid. No current directory status can be established; ask the host administrator to review it.</p></div></div>';
			return;}
		foreach ( ( new WordPressDirectoryInventory() )->all() as $item ) {
			$row        = $state['records'][ $item['key'] ] ?? null;
			$historical = is_array( $row ) && ( $row['fingerprint'] !== $item['fingerprint'] || $row['checked_at'] > $now || $now - $row['checked_at'] >= 86400 );
			echo '<section class="amsec-file-scan"><div class="amsec-file-heading"><h2>' . esc_html( $item['label'] ) . '</h2><span class="amsec-file-rule-age">Installed ' . esc_html( $item['version'] ) . '</span></div>';
			if ( null === $row ) {
				echo '<p>No directory observation recorded.</p>';} else {
							$result = $row['result'];
							$label  = match ( $result['state'] ) {
					'closed'=>'Directory closure observed', 'listed'=>'Directory listing observed', default=>'Current directory status unknown'};
					echo '<div class="amsec-file-status"><strong>' . esc_html( ( $historical ? 'Historical: ' : '' ) . $label ) . '</strong><span>Observed UTC ' . esc_html( gmdate( 'Y-m-d H:i:s', $row['checked_at'] ) ) . '</span></div>';
					if ( 'closed' === $result['state'] ) {
						$this->closure( $result );
					} elseif ( 'listed' === $result['state'] ) {
						echo '<p>Directory version observed: ' . esc_html( $result['version'] ) . '. Repository update UTC: ' . esc_html( null === $result['updated_at'] ? 'Unknown' : gmdate( 'Y-m-d H:i:s', $result['updated_at'] ) ) . '.</p>';
						if ( $result['old_update'] ) {
								echo '<p>Old repository update: more than 730 days before this observation. Review maintenance and compatibility; age alone does not prove abandonment.</p>';}
					}
					if ( null !== $row['last_closed'] && 'closed' !== $result['state'] ) {
						echo '<details><summary>Earlier closure observation retained</summary><p>This is historical evidence; it does not establish current closure. Observed UTC ' . esc_html( gmdate( 'Y-m-d H:i:s', $row['last_closed']['checked_at'] ) ) . '.</p>';
						$this->closure( $row['last_closed']['result'] );
						echo '</details>';}
				}
				if ( $item['supported'] ) {
					echo '<p>Candidate directory slug: ' . esc_html( $item['slug'] ) . '. <a href="' . esc_url( 'https://wordpress.org/plugins/' . rawurlencode( $item['slug'] ) . '/' ) . '" target="_blank" rel="noopener noreferrer">Review the directory record</a></p><form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="amsec_repository_lookup"><input type="hidden" name="target" value="' . esc_attr( $item['key'] ) . '"><input type="hidden" name="fingerprint" value="' . esc_attr( $item['fingerprint'] ) . '">';
					wp_nonce_field( 'amsec_repository_' . $item['key'] . '_' . $item['fingerprint'] );
					echo '<p><label><input type="checkbox" name="consent" value="1" required> Send this candidate slug to WordPress.org for a directory-status lookup.</label></p>';
					submit_button( __( 'Look up directory status', 'amazing-security' ), 'secondary', 'submit', false );
					echo '</form>';
				} else {
					echo '<p>Unsupported package for this lookup. Ask its publisher about maintenance; no absence or abandonment is inferred.</p>';}
				echo '</section>';
		}
		echo '</div>';
	}
	private function closure( array $result ): void {
		$reason = match ( $result['reason'] ) {
			'security-issue'=>'Security issue', 'author-request'=>'Author request', 'guideline-violation'=>'Guideline violation', 'licensing-trademark-violation'=>'Licensing or trademark violation', 'unused'=>'Unused', default=>'Not publicly established'};
		echo '<p>Closure date UTC: ' . esc_html( '' === $result['closed_date'] ? 'Unknown' : $result['closed_date'] ) . '. Public directory reason: ' . esc_html( $reason ) . '. Review the official record and supported alternatives before making a change.</p>';
	}
}
