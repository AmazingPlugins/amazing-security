<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Headers;

final class HeaderPage {
	public function __construct( private readonly ?HeaderService $service = null ) {}
	public function register(): void {
		$hook = add_submenu_page( 'amazing-security', 'Security headers', 'Security headers', 'manage_options', 'amsec-headers', array( $this, 'render' ) );
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
		$s     = $this->service ?? ( new WordPressHeaderService() )->create();
		$state = $s->status();
		$fp    = $s->fingerprint();
		echo '<div class="wrap amazing-security-admin"><header class="amsec-header"><div><h1>Security headers</h1><p>Review selected response protections without changing site behavior.</p></div></header><section class="amsec-overview"><h2>Server-side HEAD observation</h2><p>An optional anonymous HEAD request checks the configured homepage from this server. Its route and response may differ from a visitor’s browser GET, CDN, login, checkout or other pages. Header presence does not prove an effective policy, safe CSP, browser enforcement or compliance.</p><p>Public IPv4 and standard HTTP/HTTPS ports only. Requests use a validated pinned address, verified TLS, no cookies, proxy or redirects, and a five-second transfer timeout. DNS can take longer. Private, IPv6-only, unresolved, unsupported and non-HTML/error responses remain unknown. Hosts without cURL are unsupported. No hosted scanning service is used.</p><p>Header enforcement is unchanged. Review any policy rollout with the host administrator and test WooCommerce, forms, embeds and login first.</p></section>';
		if ( ! empty( $state['invalid'] ) ) {
			echo '<div class="notice notice-error"><p>Stored assessment is invalid. No response coverage can be established.</p></div></div>';
			return;}
		echo '<section class="amsec-file-scan"><h2>Assess the configured homepage</h2><form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="amsec_headers_check"><input type="hidden" name="fingerprint" value="' . esc_attr( $fp ) . '">';
		wp_nonce_field( 'amsec_headers_' . $fp );
		echo '<p><label><input type="checkbox" name="consent" value="1" required> I agree to one anonymous request to the configured homepage. The destination sees the server IP and generic user agent. Raw headers and the target URL are not stored.</label></p>';
		submit_button( 'Assess homepage headers', 'secondary' );
		echo '<p>Checks for the same target have a ten-minute cooldown. No scheduled requests or automatic policy changes.</p></form></section>';
		foreach ( array(
			'latest'    => 'Latest attempt',
			'last_good' => 'Last assessed response',
		) as $key => $label ) {
			$r = $state[ $key ];
			if ( null === $r ) {
				continue;
			}$historical = $r['fingerprint'] !== $fp || time() < $r['captured_at'] || time() - $r['captured_at'] >= 86400;
			echo '<section class="amsec-file-scan"><h2>' . esc_html( $label ) . '</h2><p>' . esc_html( 'Captured UTC: ' . gmdate( 'Y-m-d H:i:s', $r['captured_at'] ) . ( $historical ? ' — historical or changed target.' : '.' ) ) . '</p>';
			if ( 'unknown' === $r['result']['state'] ) {
				echo '<p>Unknown or unsupported response. No absent-header verdict is established. A previous assessed response, if retained, remains historical evidence.</p></section>';
					continue;
			}echo '<table class="widefat striped amsec-stacked-table"><thead><tr><th>Protection</th><th>Observed state</th><th>Review guidance</th></tr></thead><tbody>';
			foreach ( $r['result']['headers'] as $name => $value ) {
				[$title, $guide] = match ( $name ) {
					'hsts'=>array( 'HSTS', 'A positive recognized max-age is an observation only. HTTP is ineffective; zero disables the policy. Verify HTTPS for all intended hosts before changing it.' ), 'content_type'=>array( 'Content type protection', 'Recognized means nosniff was observed on this HEAD response. Verify actual served MIME types.' ), 'framing'=>array( 'Framing', 'Recognized means DENY or SAMEORIGIN. Review embeds and CSP frame-ancestors separately; absence here does not establish no framing protection.' ), 'referrer'=>array( 'Referrer policy', 'Recognized syntax can still disclose information. Choose the policy that fits the site.' ), 'csp'=>array( 'Enforcing CSP', 'Presence requires policy review. No source-list, nonce, reporting or effectiveness verdict is made.' ), default=>array( 'CSP report-only', 'A report-only policy does not enforce resource restrictions. Review reporting behavior before rollout.' )};
				echo '<tr><td data-label="Protection">' . esc_html( $title ) . '</td><td data-label="State">' . esc_html( $value ) . '</td><td data-label="Guidance">' . esc_html( $guide ) . '</td></tr>';
			}echo '</tbody></table><p>Missing means absent from this observed response; review means duplicate, empty or unrecognized selected value. Recognized is not a security grade.</p></section>';}
		echo '</div>';
	}
}
