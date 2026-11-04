<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Integrity\WordPressOptions;
use AmazingPlugins\Security\Login\WordPressLoginSettings;
use AmazingPlugins\Security\Login\WordPressRateCounterStore;
use InvalidArgumentException;

final class LoginSettingsAction {
	public static function parse( array $post ): array {
		$mode = $post['rate_mode'] ?? null;
		if ( ! is_string( $mode ) || ! in_array( $mode, array( 'off', 'observe', 'block' ), true ) ) {
			throw new InvalidArgumentException( 'Invalid rate mode.' );
		}
		$xmlRpc = $post['xmlrpc_disabled'] ?? null;
		$erase  = $post['erase_on_uninstall'] ?? null;
		return array( $mode, '1' === $xmlRpc, '1' === $erase );
	}

	public function save(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You cannot change login protection.', 'ironlatch-security-scanner' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'ironlatch_login_settings' );
		try {
			$fields = array();
			foreach ( array( 'rate_mode', 'xmlrpc_disabled', 'erase_on_uninstall' ) as $field ) {
				$fields[ $field ] = isset( $_POST[ $field ] ) && is_string( $_POST[ $field ] ) ? sanitize_key( wp_unslash( $_POST[ $field ] ) ) : null;
			}
			list( $mode, $xmlRpc, $erase ) = self::parse( $fields );
			$settings                      = new WordPressLoginSettings( new WordPressOptions() );
			$settings->setRateMode( $mode );
			if ( 'off' === $mode ) {
				( new WordPressRateCounterStore( $GLOBALS['wpdb'] ) )->purge();
			}
			$settings->setXmlRpcAuthDisabled( $xmlRpc );
			$settings->setEraseOnUninstall( $erase );
		} catch ( \Throwable ) {
			wp_die( esc_html__( 'Login settings could not be saved.', 'ironlatch-security-scanner' ), '', array( 'response' => 400 ) );
		}
		wp_safe_redirect( admin_url( 'admin.php?page=ironlatch-accounts#sign-in' ) );
		exit;
	}
}
