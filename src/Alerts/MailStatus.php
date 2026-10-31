<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Alerts;

defined( 'ABSPATH' ) || exit;

/** WordPress admin email readiness for notifications. Transport stays the site’s wp_mail setup. */
final class MailStatus {
	/**
	 * @return array{email: string, configured: bool, summary: string}
	 */
	public static function assess( mixed $adminEmail = null ): array {
		$email = is_string( $adminEmail ) ? trim( $adminEmail ) : '';
		if ( '' === $email && function_exists( 'get_option' ) ) {
			$raw   = get_option( 'admin_email', '' );
			$email = is_string( $raw ) ? trim( $raw ) : '';
		}
		$configured = false !== filter_var( $email, FILTER_VALIDATE_EMAIL );
		return array(
			'email'      => $email,
			'configured' => $configured,
			'summary'    => $configured
				? __( 'Notifications use WordPress mail to this administrator address. Delivery depends on the mail service configured for this site.', 'amsec-security-scanner' )
				: __( 'WordPress admin email is missing or invalid. Set a valid address under Settings → General before turning notifications on.', 'amsec-security-scanner' ),
		);
	}
}
