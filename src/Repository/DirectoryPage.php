<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Repository;

defined( 'ABSPATH' ) || exit;

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
		echo '<div class="wrap amazing-security-admin"><header class="amsec-header"><div><h1>' . esc_html__( 'Plugin directory status', 'amazing-security' ) . '</h1><p>' . esc_html__( 'Optional WordPress.org directory observations for selected installed plugin candidates.', 'amazing-security' ) . '</p></div></header><section class="amsec-overview"><h2>' . esc_html__( 'Scope and privacy', 'amazing-security' ) . '</h2><p>' . esc_html__( 'Each consented lookup sends one directory slug to WordPress.org, which sees your server IP. It does not send the installed version, site URL, credentials or contents. No lookup runs automatically. Up to 100 standard plugin entries are listed; custom-update, standalone and symlink packages are unsupported.', 'amazing-security' ) . '</p><p>' . esc_html__( 'A directory slug match does not authenticate installed code. Closure is a directory observation, not a malware verdict. Missing records and old updates do not prove abandonment or a vulnerability. No plugin is deactivated or changed. Results older than 24 hours, or for a changed installation, are historical. A repeated lookup within ten minutes uses its saved result.', 'amazing-security' ) . '</p></section>';
		if ( ! empty( $state['invalid'] ) ) {
			echo '<div class="notice notice-error"><p>' . esc_html__( 'Stored advisory state is invalid. No current directory status can be established; ask the host administrator to review it.', 'amazing-security' ) . '</p></div></div>';
			return;}
		foreach ( ( new WordPressDirectoryInventory() )->all() as $item ) {
			$row        = $state['records'][ $item['key'] ] ?? null;
			$historical = is_array( $row ) && ( $row['fingerprint'] !== $item['fingerprint'] || $row['checked_at'] > $now || $now - $row['checked_at'] >= 86400 );
			echo '<section class="amsec-file-scan"><div class="amsec-file-heading"><h2>' . esc_html( $item['label'] ) . '</h2><span class="amsec-file-rule-age">Installed ' . esc_html( $item['version'] ) . '</span></div>';
			if ( null === $row ) {
				echo '<p>' . esc_html__( 'No directory observation recorded.', 'amazing-security' ) . '</p>';} else {
							$result = $row['result'];
							$label  = match ( $result['state'] ) {
					'closed'=>__( 'Directory closure observed', 'amazing-security' ), 'listed'=>__( 'Directory listing observed', 'amazing-security' ), default=>__( 'Current directory status unknown', 'amazing-security' )};
					echo '<div class="amsec-file-status"><strong>' . esc_html( ( $historical ? __( 'Historical:', 'amazing-security' ) . ' ' : '' ) . $label ) . '</strong><span>' . esc_html__( 'Observed UTC', 'amazing-security' ) . ' ' . esc_html( gmdate( 'Y-m-d H:i:s', $row['checked_at'] ) ) . '</span></div>';
					if ( 'closed' === $result['state'] ) {
						$this->closure( $result );
					} elseif ( 'listed' === $result['state'] ) {
						echo '<p>' . esc_html( sprintf( /* translators: 1: directory version, 2: repository update date and time in UTC, or "Unknown". */ __( 'Directory version observed: %1$s. Repository update UTC: %2$s.', 'amazing-security' ), $result['version'], null === $result['updated_at'] ? __( 'Unknown', 'amazing-security' ) : gmdate( 'Y-m-d H:i:s', $result['updated_at'] ) ) ) . '</p>';
						if ( $result['old_update'] ) {
								echo '<p>' . esc_html__( 'Old repository update: more than 730 days before this observation. Review maintenance and compatibility; age alone does not prove abandonment.', 'amazing-security' ) . '</p>';}
					}
					if ( null !== $row['last_closed'] && 'closed' !== $result['state'] ) {
						echo '<details><summary>' . esc_html__( 'Earlier closure observation retained', 'amazing-security' ) . '</summary><p>' . esc_html( sprintf( /* translators: %s: date and time in UTC when the earlier closure was observed. */ __( 'This is historical evidence; it does not establish current closure. Observed UTC %s.', 'amazing-security' ), gmdate( 'Y-m-d H:i:s', $row['last_closed']['checked_at'] ) ) ) . '</p>';
						$this->closure( $row['last_closed']['result'] );
						echo '</details>';}
				}
				if ( $item['supported'] ) {
					echo '<p>' . esc_html__( 'Candidate directory slug:', 'amazing-security' ) . ' ' . esc_html( $item['slug'] ) . '. <a href="' . esc_url( 'https://wordpress.org/plugins/' . rawurlencode( $item['slug'] ) . '/' ) . '" target="_blank" rel="noopener noreferrer">' . esc_html__( 'Review the directory record', 'amazing-security' ) . '</a></p><form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="amsec_repository_lookup"><input type="hidden" name="target" value="' . esc_attr( $item['key'] ) . '"><input type="hidden" name="fingerprint" value="' . esc_attr( $item['fingerprint'] ) . '">';
					wp_nonce_field( 'amsec_repository_' . $item['key'] . '_' . $item['fingerprint'] );
					echo '<p><label><input type="checkbox" name="consent" value="1" required> ' . esc_html__( 'Send this candidate slug to WordPress.org for a directory-status lookup.', 'amazing-security' ) . '</label></p>';
					submit_button( __( 'Look up directory status', 'amazing-security' ), 'secondary', 'submit', false );
					echo '</form>';
				} else {
					echo '<p>' . esc_html__( 'Unsupported package for this lookup. Ask its publisher about maintenance; no absence or abandonment is inferred.', 'amazing-security' ) . '</p>';}
				echo '</section>';
		}
		echo '</div>';
	}
	private function closure( array $result ): void {
		$reason = match ( $result['reason'] ) {
			'security-issue'=>__( 'Security issue', 'amazing-security' ), 'author-request'=>__( 'Author request', 'amazing-security' ), 'guideline-violation'=>__( 'Guideline violation', 'amazing-security' ), 'licensing-trademark-violation'=>__( 'Licensing or trademark violation', 'amazing-security' ), 'unused'=>__( 'Unused', 'amazing-security' ), default=>__( 'Not publicly established', 'amazing-security' )};
		echo '<p>' . esc_html( sprintf( /* translators: 1: closure date in UTC, or "Unknown"; 2: public directory reason. */ __( 'Closure date UTC: %1$s. Public directory reason: %2$s. Review the official record and supported alternatives before making a change.', 'amazing-security' ), '' === $result['closed_date'] ? __( 'Unknown', 'amazing-security' ) : $result['closed_date'], $reason ) ) . '</p>';
	}
}
