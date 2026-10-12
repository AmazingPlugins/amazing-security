<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Free\Recovery;

/** Recovery submenu. Changes run from POST handlers, never from the page view. */
final class Module {
	public static function boot(): void {
		add_action( 'admin_menu', array( self::class, 'menu' ) );
		add_action( 'admin_post_amsec_recovery_backup', array( self::class, 'backup' ) );
		add_action( 'admin_post_amsec_recovery_delete', array( self::class, 'delete' ) );
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
		echo '<p>' . esc_html__( 'These tools act only after you submit a form. You can download your database tables or move one unexpected file out of the site. A finished action does not mean the site is clean.', 'amazing-security' ) . '</p>';
		self::notice();
		if ( ! $https ) {
			echo '<div class="notice inline notice-error"><p>' . esc_html( ( new Approval( false, true, true ) )->denial() ?? '' ) . '</p></div>';
		}
		if ( ! \AmazingPlugins\Security\Files\FileMods::allowed() ) {
			echo '<div class="notice inline notice-warning"><p>' . esc_html( \AmazingPlugins\Security\Files\FileMods::denial() ) . '</p></div>';
		}
		if ( $https ) {
			self::renderBackup();
			if ( \AmazingPlugins\Security\Files\FileMods::allowed() ) {
				self::renderDelete();
			}
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

	public static function delete(): void {
		self::guard( 'amsec_recovery_delete' );
		\AmazingPlugins\Security\Files\FileMods::requireAllowed();
		// phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Nonce checked in guard. The delete service checks the typed path.
		$path = isset( $_POST['path'] ) && is_string( $_POST['path'] ) ? wp_unslash( $_POST['path'] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- The path is checked against an allowlist.
		// phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- The confirmation must be the exact phrase DELETE.
		$phrase = isset( $_POST['phrase'] ) ? sanitize_text_field( wp_unslash( $_POST['phrase'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce checked in guard().
		$main   = defined( 'AMAZING_SECURITY_FILE' ) ? AMAZING_SECURITY_FILE : '';
		$result = ( new UnexpectedFile( ABSPATH, is_string( $main ) ? $main : '', sys_get_temp_dir() ) )->remove( $path, $phrase, self::approval() );
		self::finish( $result, 'delete' );
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

	private static function renderDelete(): void {
		echo '<h2>' . esc_html__( 'Remove an unexpected file', 'amazing-security' ) . '</h2>';
		echo '<p>' . esc_html__( 'Type a path under uploads, a theme, or a plugin. Type DELETE to confirm. The plugin main file, wp-config.php, and .htaccess stay.', 'amazing-security' ) . '</p>';
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
		echo '<input type="hidden" name="action" value="amsec_recovery_delete">';
		wp_nonce_field( 'amsec_recovery_delete' );
		echo '<p><label>' . esc_html__( 'Relative path', 'amazing-security' ) . ' <input type="text" name="path" class="regular-text code" maxlength="1024" autocomplete="off" required></label></p>';
		echo '<p><label>' . esc_html__( 'Confirmation', 'amazing-security' ) . ' <input type="text" name="phrase" value="" autocomplete="off" spellcheck="false"></label></p>';
		echo '<p><button class="button" type="submit">' . esc_html__( 'Remove file', 'amazing-security' ) . '</button></p></form>';
	}

	private static function notice(): void {
		$code     = isset( $_GET['amsec_recovery'] ) && is_string( $_GET['amsec_recovery'] ) ? sanitize_key( wp_unslash( $_GET['amsec_recovery'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Allowlisted status on GET. Changes are separate POST actions.
		$messages = array(
			'delete' => __( 'The file was moved out of the site into a private temp backup.', 'amazing-security' ),
		);
		if ( isset( $messages[ $code ] ) ) {
			$key     = 'amsec_recovery_msg_' . get_current_user_id();
			$detail  = get_transient( $key );
			$message = is_string( $detail ) && '' !== $detail ? $detail : $messages[ $code ];
			delete_transient( $key );
			echo '<div class="notice inline notice-success"><p>' . esc_html( $message ) . '</p></div>';
		}
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

	private static function finish( ChangeResult $result, string $code ): void {
		if ( ! $result->ok ) {
			wp_die( esc_html( $result->message ), '', array( 'response' => 400 ) );
		}
		set_transient( 'amsec_recovery_msg_' . get_current_user_id(), $result->message, MINUTE_IN_SECONDS );
		wp_safe_redirect( admin_url( 'admin.php?page=amsec-recovery&amsec_recovery=' . rawurlencode( $code ) ) );
		exit;
	}
}
