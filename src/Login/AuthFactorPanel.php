<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Login;

/** Status-only card for passkeys / authenticator apps. */
final class AuthFactorPanel {
	/**
	 * @param array{state:string,provider:string,suggest_slug:string,suggest_name:string} $factor
	 */
	public static function html( string $title, array $factor, string $directoryUrl, string $domId = 'factor' ): string {
		$state = $factor['state'] ?? AuthFactorStatus::MISSING;
		$label = match ( $state ) {
			AuthFactorStatus::ACTIVE    => __( 'Active', 'amazing-security' ),
			AuthFactorStatus::AVAILABLE => __( 'Available, off', 'amazing-security' ),
			default                     => __( 'Not on this site', 'amazing-security' ),
		};
		$safe  = preg_replace( '/[^a-z0-9\-]+/', '-', strtolower( $domId ) );
		$id    = is_string( $safe ) && '' !== $safe ? $safe : 'factor';
		$html  = '<section class="amsec-auth-factor" aria-labelledby="amsec-auth-factor-' . esc_attr( $id ) . '">';
		$html .= '<h2 id="amsec-auth-factor-' . esc_attr( $id ) . '">' . esc_html( $title ) . '</h2>';
		$html .= '<p><strong class="amsec-auth-factor-state">' . esc_html( $label ) . '</strong></p>';
		if ( AuthFactorStatus::MISSING === $state ) {
			$html .= '<p>' . esc_html__( 'Amazing Security does not provide this sign-in factor. Install a dedicated plugin, turn it on there, then come back to confirm the status.', 'amazing-security' ) . '</p>';
			$name  = (string) ( $factor['suggest_name'] ?? 'Two Factor' );
			$html .= '<p><a class="button" href="' . esc_url( $directoryUrl ) . '">' . esc_html(
				sprintf(
					/* translators: %s: suggested plugin name */
					__( 'View %s on WordPress.org', 'amazing-security' ),
					$name
				)
			) . '</a></p>';
		} elseif ( AuthFactorStatus::AVAILABLE === $state ) {
			$provider = (string) ( $factor['provider'] ?? '' );
			$html    .= '<p>' . esc_html(
				sprintf(
					/* translators: %s: installed plugin name */
					__( '%s is installed. Turn it on and enroll from that plugin’s screens. Amazing Security only reports the status.', 'amazing-security' ),
					$provider
				)
			) . '</p>';
		} else {
			$provider = (string) ( $factor['provider'] ?? '' );
			$html    .= '<p>' . esc_html(
				sprintf(
					/* translators: %s: installed plugin name */
					__( '%s is handling this factor. Manage enrollment and backup codes there.', 'amazing-security' ),
					$provider
				)
			) . '</p>';
		}
		$html .= '</section>';
		return $html;
	}
}
