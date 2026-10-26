<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Free\Recovery;

defined( 'ABSPATH' ) || exit;

/** Recovery submenu: read-only directory modes and a database SQL download. */
final class Module {
	public static function boot(): void {
		add_action( 'admin_menu', array( self::class, 'menu' ) );
		add_action( 'admin_post_amsec_recovery_backup', array( self::class, 'backup' ) );
	}

	public static function menu(): void {
		add_submenu_page( 'amazing-security', __( 'Recovery', 'amazing-security' ), __( 'Recovery', 'amazing-security' ), 'manage_options', 'amsec-recovery', array( self::class, 'render' ) );
	}

	public static function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to run recovery tools.', 'amazing-security' ), '', array( 'response' => 403 ) );
		}
		$https = is_ssl();
		echo '<div class="wrap amazing-security-admin"><h1>' . esc_html__( 'Recovery', 'amazing-security' ) . '</h1>';
		echo '<p>' . esc_html__( 'Directory modes are shown for review. Change them in your hosting file manager or over SFTP.', 'amazing-security' ) . '</p>';
		if ( ! $https ) {
			echo '<div class="notice notice-error inline"><p>' . esc_html( ( new Approval( false, true, true ) )->denial() ?? '' ) . '</p></div>';
		}
		self::renderModes();
		if ( $https ) {
			self::renderBackup();
		}
		echo '</div>';
	}

	public static function backup(): void {
		self::guard( 'amsec_recovery_backup' );
		global $wpdb;
		if ( ! isset( $wpdb ) || ! is_object( $wpdb ) || ! is_string( $wpdb->prefix ) ) {
			wp_die( esc_html__( 'The database connection is unavailable. No SQL file was created.', 'amazing-security' ), '', array( 'response' => 400 ) );
		}
		$confirmed = isset( $_POST['confirm'] ) && '1' === sanitize_text_field( wp_unslash( $_POST['confirm'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce checked in guard().
		$result    = ( new DatabaseDump( new WordPressTables( $wpdb ), array( WordPressTables::class, 'escape' ) ) )->build( $wpdb->prefix, self::approval(), $confirmed );
		if ( ! $result->ok || '' === $result->body || preg_match( '/CREATE\s+DATABASE/i', $result->body ) ) {
			wp_die( esc_html( '' === $result->message ? __( 'No SQL file was created.', 'amazing-security' ) : $result->message ), '', array( 'response' => 400 ) );
		}
		nocache_headers();
		header( 'Content-Type: application/octet-stream' );
		header( 'Content-Disposition: attachment; filename="amsec-database.sql"' );
		header( 'Content-Length: ' . (string) strlen( $result->body ) );
		header( 'X-Content-Type-Options: nosniff' );
		echo $result->body; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- SQL download body, not HTML.
		exit;
	}

	private static function renderModes(): void {
		echo '<h2>' . esc_html__( 'Directory modes', 'amazing-security' ) . '</h2>';
		echo '<p>' . esc_html__( 'The suggested mode for these directories is 0755. 0777 lets any user on the server write to them.', 'amazing-security' ) . '</p>';
		echo '<table class="widefat striped"><thead><tr><th>' . esc_html__( 'Directory', 'amazing-security' ) . '</th><th>' . esc_html__( 'Current mode', 'amazing-security' ) . '</th><th>' . esc_html__( 'Suggested mode', 'amazing-security' ) . '</th></tr></thead><tbody>';
		foreach ( DirectoryModes::forSite()->preview() as $row ) {
			echo '<tr><td><code>' . esc_html( $row['path'] ) . '</code></td><td>' . esc_html( null === $row['octal'] ? __( 'Unavailable', 'amazing-security' ) : $row['octal'] ) . '</td><td><code>' . esc_html( $row['suggested'] ) . '</code></td></tr>';
		}
		echo '</tbody></table>';
	}

	private static function renderBackup(): void {
		echo '<h2>' . esc_html__( 'Database backup', 'amazing-security' ) . '</h2>';
		echo '<p>' . esc_html__( 'Downloads tables whose names start with the site prefix. The file is not saved in the plugin or uploads. More than 50 tables, or more than 20 MB, is refused instead of a partial file.', 'amazing-security' ) . '</p>';
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
		echo '<input type="hidden" name="action" value="amsec_recovery_backup">';
		wp_nonce_field( 'amsec_recovery_backup' );
		echo '<p><label><input type="checkbox" name="confirm" value="1"> ' . esc_html__( 'Download the prefixed tables.', 'amazing-security' ) . '</label></p>';
		echo '<p><button class="button button-primary" type="submit">' . esc_html__( 'Download SQL', 'amazing-security' ) . '</button></p></form>';
	}

	private static function guard( string $action ): void {
		$method = isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( sanitize_text_field( wp_unslash( (string) $_SERVER['REQUEST_METHOD'] ) ) ) : '';
		if ( 'POST' !== $method ) {
			wp_die( esc_html__( 'Recovery tools run only from a submitted form.', 'amazing-security' ), '', array( 'response' => 405 ) );
		}
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to run recovery tools.', 'amazing-security' ), '', array( 'response' => 403 ) );
		}
		if ( ! is_ssl() ) {
			wp_die( esc_html__( 'Recovery tools need HTTPS. No files were changed.', 'amazing-security' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( $action );
	}

	private static function approval(): Approval {
		return new Approval( true, true, true );
	}
}
