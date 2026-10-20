<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Headers;

defined( 'ABSPATH' ) || exit;

final class HeaderPage {
	public function __construct( private readonly ?HeaderService $service = null ) {}
	public function register(): void {
		$hook = add_submenu_page( 'amazing-security', __( 'Security headers', 'amazing-security' ), __( 'Security headers', 'amazing-security' ), 'manage_options', 'amsec-headers', array( $this, 'render' ) );
		add_action(
			'admin_enqueue_scripts',
			static function ( string $current ) use ( $hook ): void {
				if ( $current === $hook ) {
					wp_enqueue_style( 'amazing-security-admin', plugins_url( 'assets/admin.css', AMAZING_SECURITY_FILE ), array(), '0.1.0' );
				}}
		);
	}
	private function stateLabel( string $value ): string {
		return match ( $value ) {
			'missing'     => __( 'Missing', 'amazing-security' ),
			'present'     => __( 'Present', 'amazing-security' ),
			'recognized'  => __( 'Recognized', 'amazing-security' ),
			'positive'    => __( 'Positive', 'amazing-security' ),
			'disabled'    => __( 'Disabled', 'amazing-security' ),
			'ineffective' => __( 'Ineffective', 'amazing-security' ),
			'review'      => __( 'Review', 'amazing-security' ),
			'unknown'     => __( 'Unknown', 'amazing-security' ),
			default       => $value,
		};
	}
	public function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'amazing-security' ), '', array( 'response' => 403 ) );}
		$s     = $this->service ?? ( new WordPressHeaderService() )->create();
		$state = $s->status();
		$fp    = $s->fingerprint();
		echo '<div class="wrap amazing-security-admin"><header class="amsec-header"><div><h1>' . esc_html__( 'Security headers', 'amazing-security' ) . '</h1><p>' . esc_html__( 'Review selected response protections without changing site behavior.', 'amazing-security' ) . '</p></div></header><section class="amsec-overview"><h2>' . esc_html__( 'Server-side HEAD observation', 'amazing-security' ) . '</h2><p>' . esc_html__( 'An optional anonymous HEAD request checks the configured homepage from this server. Its route and response may differ from a visitor’s browser GET, CDN, login, checkout or other pages. Header presence does not prove an effective policy, safe CSP, browser enforcement or compliance.', 'amazing-security' ) . '</p><p>' . esc_html__( 'Standard HTTP and HTTPS ports only. The request goes through the WordPress HTTP API with verified TLS, no cookies and no redirects, and gives up after five seconds. Unresolved, error and non-HTML responses stay unknown. No hosted scanning service is used.', 'amazing-security' ) . '</p><p>' . esc_html__( 'Header enforcement is unchanged. Review any policy rollout with the host administrator and test WooCommerce, forms, embeds and login first.', 'amazing-security' ) . '</p></section>';
		if ( ! empty( $state['invalid'] ) ) {
			echo '<div class="notice notice-error"><p>' . esc_html__( 'Stored assessment is invalid. No response coverage can be established.', 'amazing-security' ) . '</p></div></div>';
			return;}
		echo '<section class="amsec-file-scan"><h2>' . esc_html__( 'Assess the configured homepage', 'amazing-security' ) . '</h2><form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="amsec_headers_check"><input type="hidden" name="fingerprint" value="' . esc_attr( $fp ) . '">';
		wp_nonce_field( 'amsec_headers_' . $fp );
		echo '<p><label><input type="checkbox" name="consent" value="1" required> ' . esc_html__( 'I agree to one anonymous request to the configured homepage. The destination sees the server IP and generic user agent. Raw headers and the target URL are not stored.', 'amazing-security' ) . '</label></p>';
		submit_button( __( 'Assess homepage headers', 'amazing-security' ), 'secondary' );
		echo '<p>' . esc_html__( 'Checks for the same target have a ten-minute cooldown. No scheduled requests or automatic policy changes.', 'amazing-security' ) . '</p></form></section>';
		foreach ( array(
			'latest'    => __( 'Latest attempt', 'amazing-security' ),
			'last_good' => __( 'Last assessed response', 'amazing-security' ),
		) as $key => $label ) {
			$r = $state[ $key ];
			if ( null === $r ) {
				continue;
			}$historical = $r['fingerprint'] !== $fp || time() < $r['captured_at'] || time() - $r['captured_at'] >= 86400;
			/* translators: %s: UTC timestamp when the stored response was captured. */
			echo '<section class="amsec-file-scan"><h2>' . esc_html( $label ) . '</h2><p>' . esc_html( sprintf( $historical ? __( 'Captured UTC: %s — historical or changed target.', 'amazing-security' ) : __( 'Captured UTC: %s.', 'amazing-security' ), gmdate( 'Y-m-d H:i:s', $r['captured_at'] ) ) ) . '</p>';
			if ( 'unknown' === $r['result']['state'] ) {
				echo '<p>' . esc_html__( 'Unknown or unsupported response. No absent-header verdict is established. A previous assessed response, if retained, remains historical evidence.', 'amazing-security' ) . '</p></section>';
					continue;
			}echo '<table class="widefat striped amsec-stacked-table"><thead><tr><th>' . esc_html__( 'Protection', 'amazing-security' ) . '</th><th>' . esc_html__( 'Observed state', 'amazing-security' ) . '</th><th>' . esc_html__( 'Review guidance', 'amazing-security' ) . '</th></tr></thead><tbody>';
			foreach ( $r['result']['headers'] as $name => $value ) {
				[$title, $guide] = match ( $name ) {
					'hsts'=>array( __( 'HSTS', 'amazing-security' ), __( 'A positive recognized max-age is an observation only. HTTP is ineffective; zero disables the policy. Verify HTTPS for all intended hosts before changing it.', 'amazing-security' ) ), 'content_type'=>array( __( 'Content type protection', 'amazing-security' ), __( 'Recognized means nosniff was observed on this HEAD response. Verify actual served MIME types.', 'amazing-security' ) ), 'framing'=>array( __( 'Framing', 'amazing-security' ), __( 'Recognized means DENY or SAMEORIGIN. Review embeds and CSP frame-ancestors separately; absence here does not establish no framing protection.', 'amazing-security' ) ), 'referrer'=>array( __( 'Referrer policy', 'amazing-security' ), __( 'Recognized syntax can still disclose information. Choose the policy that fits the site.', 'amazing-security' ) ), 'csp'=>array( __( 'Enforcing CSP', 'amazing-security' ), __( 'Presence requires policy review. No source-list, nonce, reporting or effectiveness verdict is made.', 'amazing-security' ) ), default=>array( __( 'CSP report-only', 'amazing-security' ), __( 'A report-only policy does not enforce resource restrictions. Review reporting behavior before rollout.', 'amazing-security' ) )};
				echo '<tr><td data-label="' . esc_attr__( 'Protection', 'amazing-security' ) . '">' . esc_html( $title ) . '</td><td data-label="' . esc_attr__( 'State', 'amazing-security' ) . '">' . esc_html( $this->stateLabel( $value ) ) . '</td><td data-label="' . esc_attr__( 'Guidance', 'amazing-security' ) . '">' . esc_html( $guide ) . '</td></tr>';
			}echo '</tbody></table><p>' . esc_html__( 'Missing means absent from this observed response; review means duplicate, empty or unrecognized selected value. Recognized is not a security grade.', 'amazing-security' ) . '</p></section>';}
		echo '</div>';
	}
}
