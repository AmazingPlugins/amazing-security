<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Login;

defined( 'ABSPATH' ) || exit;

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
			$name     = (string) ( $factor['suggest_name'] ?? 'Two Factor' );
			$install  = str_contains( $directoryUrl, 'plugin-install.php' );
			$activate = str_contains( $directoryUrl, '/plugins.php?' );
			$html    .= '<p>' . esc_html(
				$activate
					? sprintf(
						/* translators: %s: suggested plugin name */
						__( 'Amazing Security does not provide this itself. %1$s is installed but not active. Click Activate %1$s, then Activate on the Plugins screen. Set it up under Users > Profile, then come back here to check the status.', 'amazing-security' ),
						$name
					)
					: ( $install
					? sprintf(
						/* translators: %s: suggested plugin name */
						__( 'Amazing Security does not provide this itself. Click Find %s, then Install Now and Activate on the search page. Set it up under Users > Profile, then come back here to check the status.', 'amazing-security' ),
						$name
					)
					: __( 'Amazing Security does not provide this itself. Ask a network administrator to install a dedicated plugin, then set it up under Users > Profile.', 'amazing-security' ) )
			) . '</p>';
			$html .= '<p><a class="button" href="' . esc_url( $directoryUrl ) . '">' . esc_html(
				sprintf(
					/* translators: %s: suggested plugin name */
					$activate ? __( 'Activate %s', 'amazing-security' ) : ( $install ? __( 'Find %s', 'amazing-security' ) : __( 'View %s on WordPress.org', 'amazing-security' ) ),
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
