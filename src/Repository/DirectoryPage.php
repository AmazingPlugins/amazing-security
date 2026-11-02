<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Repository;

defined( 'ABSPATH' ) || exit;

final class DirectoryPage {
	public function register(): void {
		$hook = add_submenu_page( 'ironlatch-security-scanner', __( 'Plugin directory status', 'ironlatch-security-scanner' ), __( 'Directory status', 'ironlatch-security-scanner' ), 'manage_options', 'ironlatch-repository', array( $this, 'render' ) );
		add_action(
			'admin_enqueue_scripts',
			static function ( string $current ) use ( $hook ): void {
				if ( $current === $hook ) {
					wp_enqueue_style( 'ironlatch-security-scanner-admin', plugins_url( 'assets/admin.css', IRONLATCH_SECURITY_SCANNER_FILE ), array(), '0.1.0' );
				}}
		);
	}
	public function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'ironlatch-security-scanner' ), '', array( 'response' => 403 ) );}
		$state = ( new WordPressDirectoryService() )->create()->status();
		$now   = time();
		echo '<div class="wrap ironlatch-security-scanner-admin"><header class="ironlatch-header"><div><h1>' . esc_html__( 'Plugin directory status', 'ironlatch-security-scanner' ) . '</h1><p>' . esc_html__( 'Optional WordPress.org directory observations for selected installed plugin candidates.', 'ironlatch-security-scanner' ) . '</p></div></header><section class="ironlatch-overview"><h2>' . esc_html__( 'Scope and privacy', 'ironlatch-security-scanner' ) . '</h2><p>' . esc_html__( 'Each consented lookup sends one directory slug to WordPress.org, which sees your server IP. It does not send the installed version, site URL, credentials or contents. No lookup runs automatically. Up to 100 standard plugin entries are listed; custom-update, standalone and symlink packages are unsupported.', 'ironlatch-security-scanner' ) . '</p><p>' . esc_html__( 'A directory slug match does not authenticate installed code. Closure is a directory observation, not a malware verdict. Missing records and old updates do not prove abandonment or a vulnerability. No plugin is deactivated or changed. Results older than 24 hours, or for a changed installation, are historical. A repeated lookup within ten minutes uses its saved result.', 'ironlatch-security-scanner' ) . '</p></section>';
		if ( ! empty( $state['invalid'] ) ) {
			echo '<div class="notice notice-error"><p>' . esc_html__( 'Stored advisory state is invalid. No current directory status can be established; ask the host administrator to review it.', 'ironlatch-security-scanner' ) . '</p></div></div>';
			return;}
		foreach ( ( new WordPressDirectoryInventory() )->all() as $item ) {
			$row        = $state['records'][ $item['key'] ] ?? null;
			$historical = is_array( $row ) && ( $row['fingerprint'] !== $item['fingerprint'] || $row['checked_at'] > $now || $now - $row['checked_at'] >= 86400 );
			echo '<section class="ironlatch-file-scan"><div class="ironlatch-file-heading"><h2>' . esc_html( $item['label'] ) . '</h2><span class="ironlatch-file-rule-age">' . sprintf( /* translators: %s: installed plugin version. */ esc_html__( 'Installed %s', 'ironlatch-security-scanner' ), esc_html( $item['version'] ) ) . '</span></div>';
			if ( null === $row ) {
				echo '<p>' . esc_html__( 'No directory observation recorded.', 'ironlatch-security-scanner' ) . '</p>';} else {
							$result = $row['result'];
							$label  = match ( $result['state'] ) {
					'closed'=>__( 'Directory closure observed', 'ironlatch-security-scanner' ), 'listed'=>__( 'Directory listing observed', 'ironlatch-security-scanner' ), default=>__( 'Current directory status unknown', 'ironlatch-security-scanner' )};
					echo '<div class="ironlatch-file-status"><strong>' . esc_html( ( $historical ? __( 'Historical:', 'ironlatch-security-scanner' ) . ' ' : '' ) . $label ) . '</strong><span>' . esc_html__( 'Observed UTC', 'ironlatch-security-scanner' ) . ' ' . esc_html( gmdate( 'Y-m-d H:i:s', $row['checked_at'] ) ) . '</span></div>';
					if ( 'closed' === $result['state'] ) {
						$this->closure( $result );
					} elseif ( 'listed' === $result['state'] ) {
						echo '<p>' . esc_html( sprintf( /* translators: 1: directory version, 2: repository update date and time in UTC, or "Unknown". */ __( 'Directory version observed: %1$s. Repository update UTC: %2$s.', 'ironlatch-security-scanner' ), $result['version'], null === $result['updated_at'] ? __( 'Unknown', 'ironlatch-security-scanner' ) : gmdate( 'Y-m-d H:i:s', $result['updated_at'] ) ) ) . '</p>';
						if ( $result['old_update'] ) {
								echo '<p>' . esc_html__( 'Old repository update: more than 730 days before this observation. Review maintenance and compatibility; age alone does not prove abandonment.', 'ironlatch-security-scanner' ) . '</p>';}
					}
					if ( null !== $row['last_closed'] && 'closed' !== $result['state'] ) {
						echo '<details><summary>' . esc_html__( 'Earlier closure observation retained', 'ironlatch-security-scanner' ) . '</summary><p>' . esc_html( sprintf( /* translators: %s: date and time in UTC when the earlier closure was observed. */ __( 'This is historical evidence; it does not establish current closure. Observed UTC %s.', 'ironlatch-security-scanner' ), gmdate( 'Y-m-d H:i:s', $row['last_closed']['checked_at'] ) ) ) . '</p>';
						$this->closure( $row['last_closed']['result'] );
						echo '</details>';}
				}
				if ( $item['supported'] ) {
					echo '<p>' . esc_html__( 'Candidate directory slug:', 'ironlatch-security-scanner' ) . ' ' . esc_html( $item['slug'] ) . '. <a href="' . esc_url( 'https://wordpress.org/plugins/' . rawurlencode( $item['slug'] ) . '/' ) . '" target="_blank" rel="noopener noreferrer">' . esc_html__( 'Review the directory record', 'ironlatch-security-scanner' ) . '</a></p><form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="ironlatch_repository_lookup"><input type="hidden" name="target" value="' . esc_attr( $item['key'] ) . '"><input type="hidden" name="fingerprint" value="' . esc_attr( $item['fingerprint'] ) . '">';
					wp_nonce_field( 'ironlatch_repository_' . $item['key'] . '_' . $item['fingerprint'] );
					echo '<p><label><input type="checkbox" name="consent" value="1" required> ' . esc_html__( 'Send this candidate slug to WordPress.org for a directory-status lookup.', 'ironlatch-security-scanner' ) . '</label></p>';
					submit_button( __( 'Look up directory status', 'ironlatch-security-scanner' ), 'secondary', 'submit', false );
					echo '</form>';
				} else {
					echo '<p>' . esc_html__( 'Unsupported package for this lookup. Ask its publisher about maintenance; no absence or abandonment is inferred.', 'ironlatch-security-scanner' ) . '</p>';}
				echo '</section>';
		}
		echo '</div>';
	}
	private function closure( array $result ): void {
		$reason = match ( $result['reason'] ) {
			'security-issue'=>__( 'Security issue', 'ironlatch-security-scanner' ), 'author-request'=>__( 'Author request', 'ironlatch-security-scanner' ), 'guideline-violation'=>__( 'Guideline violation', 'ironlatch-security-scanner' ), 'licensing-trademark-violation'=>__( 'Licensing or trademark violation', 'ironlatch-security-scanner' ), 'unused'=>__( 'Unused', 'ironlatch-security-scanner' ), default=>__( 'Not publicly established', 'ironlatch-security-scanner' )};
		echo '<p>' . esc_html( sprintf( /* translators: 1: closure date in UTC, or "Unknown"; 2: public directory reason. */ __( 'Closure date UTC: %1$s. Public directory reason: %2$s. Review the official record and supported alternatives before making a change.', 'ironlatch-security-scanner' ), '' === $result['closed_date'] ? __( 'Unknown', 'ironlatch-security-scanner' ) : $result['closed_date'], $reason ) ) . '</p>';
	}
}
