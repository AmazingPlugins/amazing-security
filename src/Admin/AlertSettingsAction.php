<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

use AmazingPlugins\Security\Integrity\WordPressOptions;
use InvalidArgumentException;

final class AlertSettingsAction {
	public static function parse( array $post ): bool {
		$value = $post['enabled'] ?? null;
		if ( ! is_string( $value ) || ! in_array( $value, array( '0', '1' ), true ) ) {
			throw new InvalidArgumentException( 'Invalid alert setting.' );
		}
		return '1' === $value;
	}

	public function save(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You cannot change security alerts.', 'amazing-security' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'amsec_alert_settings' );
		try {
			// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce checked above.
			$enabled = self::parse( wp_unslash( $_POST ) );
		} catch ( InvalidArgumentException ) {
			wp_die( esc_html__( 'Choose an alert setting.', 'amazing-security' ), '', array( 'response' => 400 ) );
		}
		$options = new WordPressOptions();
		$value   = $enabled ? '1' : '0';
		if ( $options->get( 'amsec_alerts_enabled' ) !== $value && ! $options->set( 'amsec_alerts_enabled', $value ) ) {
			wp_die( esc_html__( 'Alert setting could not be saved.', 'amazing-security' ), '', array( 'response' => 500 ) );
		}
		wp_safe_redirect( admin_url( 'admin.php?page=amsec-settings#amsec-alerts' ) );
		exit;
	}
}
