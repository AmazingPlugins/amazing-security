<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Checks;

final class WordPressValues implements Values {
	public function coreUpdateAvailable(): ?bool {
		$updates = get_site_transient( 'update_core' );
		if ( ! is_object( $updates ) || ! isset( $updates->updates ) || ! is_array( $updates->updates ) || array() === $updates->updates ) {
			return null;
		}
		foreach ( $updates->updates as $update ) {
			if ( ! is_object( $update ) || ! isset( $update->response ) ) {
				return null;
			}
			if ( 'upgrade' === $update->response ) {
				return true;
			}
		}
		return false;
	}

	public function debugDisplayed(): ?bool {
		if ( ! defined( 'WP_DEBUG_DISPLAY' ) ) {
			return null;
		}
		if ( ! WP_DEBUG_DISPLAY ) {
			return false;
		}
		return defined( 'WP_DEBUG' ) && WP_DEBUG ? true : false;
	}

	public function fileEditorDisabled(): ?bool {
		return defined( 'DISALLOW_FILE_EDIT' ) ? (bool) DISALLOW_FILE_EDIT : false;
	}

	public function adminUsesHttps(): ?bool {
		$url    = admin_url();
		$scheme = wp_parse_url( $url, PHP_URL_SCHEME );
		return is_string( $scheme ) ? 'https' === strtolower( $scheme ) : null;
	}

	public function hasDefaultAdminLogin(): ?bool {
		$users = get_users(
			array(
				'role'   => 'administrator',
				'fields' => array( 'user_login' ),
				'number' => 501,
			)
		);
		if ( ! is_array( $users ) ) {
			return null;
		}
		if ( count( $users ) > 500 ) {
			return null;
		}
		foreach ( $users as $user ) {
			if ( ! is_object( $user ) || ! isset( $user->user_login ) ) {
				return null;
			}
			if ( 'admin' === strtolower( (string) $user->user_login ) ) {
				return true;
			}
		}
		return false;
	}
}
