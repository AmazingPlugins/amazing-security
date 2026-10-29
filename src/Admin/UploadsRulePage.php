<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Checks\UploadsExecutionCheck;
use AmazingPlugins\Security\Hardening\UploadsRule;

/** Shows the Apache uploads rule and writes it only after confirmation. */
final class UploadsRulePage {
	public function register(): void {
		add_submenu_page(
			'amazing-security',
			__( 'PHP in uploads', 'amazingplugins-security-scanner' ),
			__( 'PHP in uploads', 'amazingplugins-security-scanner' ),
			'manage_options',
			'amsec-uploads',
			array( $this, 'render' )
		);
	}

	public function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'amazingplugins-security-scanner' ), '', array( 'response' => 403 ) );
		}
		$rule = UploadsExecutionCheck::classify( $this->current() );
		echo '<div class="wrap amazing-security-admin">';
		echo '<h1>' . esc_html__( 'PHP in the uploads folder', 'amazingplugins-security-scanner' ) . '</h1>';
		echo '<p>' . esc_html__( 'WordPress stores pictures and documents in uploads. Some servers will also run a PHP file that lands there. This plugin does not write a test file, and it cannot prove what this server will do.', 'amazingplugins-security-scanner' ) . '</p>';
		echo '<p>' . esc_html__( 'If the site uses Apache, you can add the rule below. Nginx and some hosts ignore that file. Ask the host if you are not sure.', 'amazingplugins-security-scanner' ) . '</p>';
		if ( '' !== $rule ) {
			echo '<p>' . esc_html__( 'A local uploads rule is already there. That still does not prove the server refuses PHP.', 'amazingplugins-security-scanner' ) . '</p>';
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only result after the confirmed write.
		$notice = isset( $_GET['amsec_uploads'] ) ? sanitize_key( wp_unslash( $_GET['amsec_uploads'] ) ) : '';
		if ( 'added' === $notice ) {
			echo '<div class="notice notice-success"><p>' . esc_html__( 'The Apache rule was added. Ask the host whether this server reads it.', 'amazingplugins-security-scanner' ) . '</p></div>';
		} elseif ( 'present' === $notice ) {
			echo '<div class="notice notice-info"><p>' . esc_html__( 'A rule was already present. Nothing was written.', 'amazingplugins-security-scanner' ) . '</p></div>';
		} elseif ( 'failed' === $notice ) {
			echo '<div class="notice notice-error"><p>' . esc_html__( 'The rule could not be written. Ask the host to add it.', 'amazingplugins-security-scanner' ) . '</p></div>';
		}
		echo '<pre>' . esc_html( UploadsRule::snippet() ) . '</pre>';
		if ( ! is_ssl() ) {
			echo '<p>' . esc_html__( 'Open this page over HTTPS to add the rule.', 'amazingplugins-security-scanner' ) . '</p></div>';
			return;
		}
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
		echo '<input type="hidden" name="action" value="amsec_uploads_rule">';
		wp_nonce_field( 'amsec_uploads_rule' );
		echo '<p><label><input type="checkbox" name="confirm" value="1" required> ' . esc_html__( 'Add this Apache rule to the uploads folder.', 'amazingplugins-security-scanner' ) . '</label></p>';
		submit_button( __( 'Add the Apache rule', 'amazingplugins-security-scanner' ) );
		echo '</form></div>';
	}

	public function save(): void {
		if ( ! current_user_can( 'manage_options' ) || ! is_ssl() ) {
			wp_die( esc_html__( 'HTTPS and administrator access are required.', 'amazingplugins-security-scanner' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'amsec_uploads_rule' );
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce checked above.
		if ( '1' !== ( isset( $_POST['confirm'] ) ? sanitize_text_field( wp_unslash( $_POST['confirm'] ) ) : '' ) ) {
			wp_die( esc_html__( 'Confirm the rule before it is written.', 'amazingplugins-security-scanner' ), '', array( 'response' => 400 ) );
		}
		$path   = $this->path();
		$result = 'failed';
		if ( '' !== $path ) {
			$existing = is_file( $path ) ? $this->read( $path ) : '';
			$next     = null === $existing ? '' : UploadsRule::merge( $existing );
			if ( null === $existing ) {
				$result = 'failed';
			} elseif ( $next === $existing ) {
				$result = 'present';
			} elseif ( $this->write( $path, $next ) ) {
				$result = 'added';
			}
		}
		wp_safe_redirect( admin_url( 'admin.php?page=amsec-uploads&amsec_uploads=' . $result ) );
		exit;
	}

	private function current(): string {
		$path = $this->path();
		if ( '' === $path || ! is_file( $path ) ) {
			return '';
		}
		$text = $this->read( $path );
		return is_string( $text ) ? $text : '';
	}

	private function path(): string {
		if ( ! function_exists( 'wp_upload_dir' ) ) {
			return '';
		}
		$upload = wp_upload_dir( null, false );
		if ( ! is_array( $upload ) || ! empty( $upload['error'] ) || ! is_string( $upload['basedir'] ?? null ) ) {
			return '';
		}
		$base = rtrim( $upload['basedir'], '/' );
		if ( strlen( $base ) > 4000 || str_contains( $base, "\0" ) || ! defined( 'WP_CONTENT_DIR' ) ) {
			return '';
		}
		$root = rtrim( WP_CONTENT_DIR, '/' );
		$real = realpath( $base );
		if ( ! is_string( $real ) || ! str_starts_with( $real, $root . '/' ) || is_link( $base ) ) {
			return '';
		}
		return $real . '/.htaccess';
	}

	private function read( string $path ): ?string {
		if ( is_link( $path ) || ! is_file( $path ) ) {
			return '';
		}
		$size = filesize( $path );
		if ( ! is_int( $size ) || $size < 0 || $size > 65536 ) {
			return null;
		}
		if ( 0 === $size ) {
			return '';
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Bounded local uploads .htaccess read.
		$text = file_get_contents( $path );
		return is_string( $text ) ? $text : null;
	}

	private function write( string $path, string $contents ): bool {
		if ( strlen( $contents ) > 65536 || is_link( $path ) ) {
			return false;
		}
		$dir = dirname( $path );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- Confirmed write is limited to the uploads directory.
		if ( is_link( $dir ) || ! is_dir( $dir ) || ! is_writable( $dir ) ) {
			return false;
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Confirmed Apache rule in the uploads folder only.
		return false !== file_put_contents( $path, $contents, LOCK_EX );
	}
}
