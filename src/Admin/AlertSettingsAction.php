<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

defined( 'ABSPATH' ) || exit;

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
			wp_die( esc_html__( 'You cannot change security alerts.', 'ironlatch-security-scanner' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'ironlatch_alert_settings' );
		try {
			$enabled = self::parse( array( 'enabled' => isset( $_POST['enabled'] ) && is_string( $_POST['enabled'] ) ? sanitize_key( wp_unslash( $_POST['enabled'] ) ) : null ) );
		} catch ( InvalidArgumentException ) {
			wp_die( esc_html__( 'Choose an alert setting.', 'ironlatch-security-scanner' ), '', array( 'response' => 400 ) );
		}
		$options = new WordPressOptions();
		$value   = $enabled ? '1' : '0';
		if ( $options->get( 'ironlatch_alerts_enabled' ) !== $value && ! $options->set( 'ironlatch_alerts_enabled', $value ) ) {
			wp_die( esc_html__( 'Alert setting could not be saved.', 'ironlatch-security-scanner' ), '', array( 'response' => 500 ) );
		}
		wp_safe_redirect( \AmazingPlugins\Security\Admin\Brand::saved( admin_url( 'admin.php?page=ironlatch-settings#ironlatch-alerts' ) ) );
		exit;
	}
}
