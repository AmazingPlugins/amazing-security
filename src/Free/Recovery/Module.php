<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Free\Recovery;

/** Recovery submenu. Changes run from POST handlers, never from the page view. */
final class Module {
	public static function boot(): void {
		add_action( 'admin_menu', array( self::class, 'menu' ) );
		add_action( 'admin_post_amsec_recovery_permission', array( self::class, 'permission' ) );
		add_action( 'admin_post_amsec_recovery_backup', array( self::class, 'backup' ) );
		add_action( 'admin_post_amsec_recovery_repair', array( self::class, 'repair' ) );
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
		echo '<p>' . esc_html__( 'These tools write only after you submit a form. A finished repair does not mean the site is clean.', 'amazing-security' ) . '</p>';
		self::notice();
		if ( ! $https ) {
			echo '<div class="notice inline notice-error"><p>' . esc_html( ( new Approval( false, true, true ) )->denial() ?? '' ) . '</p></div>';
		}
		self::renderModes( $https );
		if ( $https ) {
			self::renderBackup();
			self::renderRepair();
			self::renderDelete();
		}
		echo '</div>';
	}

	public static function permission(): void {
		self::guard( 'amsec_recovery_permission' );
		// phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Nonce checked in guard. The path must match the allowlist exactly.
		$path      = isset( $_POST['path'] ) && is_string( $_POST['path'] ) ? wp_unslash( $_POST['path'] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- The path is checked against an allowlist.
		$confirmed = isset( $_POST['confirm'] ) && '1' === sanitize_text_field( wp_unslash( $_POST['confirm'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce checked in guard().
		$result    = ( new DirectoryModes( WP_CONTENT_DIR ) )->apply( $path, self::approval(), $confirmed );
		self::finish( $result, 'mode' );
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

	public static function repair(): void {
		self::guard( 'amsec_recovery_repair' );
		// phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Nonce checked in guard. The repair service checks the path.
		$relative  = isset( $_POST['path'] ) && is_string( $_POST['path'] ) ? wp_unslash( $_POST['path'] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- The path is checked against an allowlist.
		$hash      = isset( $_POST['sha256'] ) ? strtolower( sanitize_text_field( wp_unslash( $_POST['sha256'] ) ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce checked in guard().
		$confirmed = isset( $_POST['confirm'] ) && '1' === sanitize_text_field( wp_unslash( $_POST['confirm'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce checked in guard().
		$bytes     = self::upload();
		$theme     = get_stylesheet_directory();
		$result    = ( new CoreFileRepair( ABSPATH, is_string( $theme ) ? $theme : '', sys_get_temp_dir() ) )->replace( $relative, $hash, $bytes, self::approval(), $confirmed );
		self::finish( $result, 'repair' );
	}

	public static function delete(): void {
		self::guard( 'amsec_recovery_delete' );
		// phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Nonce checked in guard. The delete service checks the typed path.
		$path = isset( $_POST['path'] ) && is_string( $_POST['path'] ) ? wp_unslash( $_POST['path'] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- The path is checked against an allowlist.
		// phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- The confirmation must be the exact phrase DELETE.
		$phrase = isset( $_POST['phrase'] ) ? sanitize_text_field( wp_unslash( $_POST['phrase'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce checked in guard().
		$main   = defined( 'AMAZING_SECURITY_FILE' ) ? AMAZING_SECURITY_FILE : '';
		$result = ( new UnexpectedFile( ABSPATH, is_string( $main ) ? $main : '', sys_get_temp_dir() ) )->remove( $path, $phrase, self::approval() );
		self::finish( $result, 'delete' );
	}

	private static function renderModes( bool $https ): void {
		echo '<h2>' . esc_html__( 'Directory modes', 'amazing-security' ) . '</h2>';
		echo '<p>' . esc_html__( 'These four directories can be set to 0755. Files inside them are left alone. 0777 is not used.', 'amazing-security' ) . '</p>';
		echo '<table class="widefat striped"><thead><tr><th>' . esc_html__( 'Directory', 'amazing-security' ) . '</th><th>' . esc_html__( 'Current mode', 'amazing-security' ) . '</th><th>' . esc_html__( 'Suggested mode', 'amazing-security' ) . '</th><th>' . esc_html__( 'Change', 'amazing-security' ) . '</th></tr></thead><tbody>';
		foreach ( ( new DirectoryModes( WP_CONTENT_DIR ) )->preview() as $row ) {
			echo '<tr><td><code>' . esc_html( $row['path'] ) . '</code></td><td>' . esc_html( null === $row['octal'] ? __( 'Unavailable', 'amazing-security' ) : $row['octal'] ) . '</td><td><code>' . esc_html( $row['suggested'] ) . '</code></td><td>';
			if ( $https && null !== $row['octal'] ) {
				echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
				echo '<input type="hidden" name="action" value="amsec_recovery_permission">';
				echo '<input type="hidden" name="path" value="' . esc_attr( $row['path'] ) . '">';
				wp_nonce_field( 'amsec_recovery_permission' );
				echo '<label><input type="checkbox" name="confirm" value="1"> ' . esc_html__( 'Set this directory to 0755.', 'amazing-security' ) . '</label> ';
				echo '<button class="button" type="submit">' . esc_html__( 'Update directory mode', 'amazing-security' ) . '</button></form>';
			}
			echo '</td></tr>';
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

	private static function renderRepair(): void {
		echo '<h2>' . esc_html__( 'Core and theme file repair', 'amazing-security' ) . '</h2>';
		echo '<p>' . esc_html__( 'Use a path under wp-includes, wp-admin, or the active theme. The uploaded bytes are written only when their SHA-256 matches, and only if that file already exists.', 'amazing-security' ) . '</p>';
		echo '<form method="post" enctype="multipart/form-data" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
		echo '<input type="hidden" name="action" value="amsec_recovery_repair">';
		wp_nonce_field( 'amsec_recovery_repair' );
		echo '<p><label>' . esc_html__( 'Relative path', 'amazing-security' ) . ' <input type="text" name="path" class="regular-text code" maxlength="1024" required></label></p>';
		echo '<p><label>' . esc_html__( 'Expected SHA-256', 'amazing-security' ) . ' <input type="text" name="sha256" class="regular-text code" minlength="64" maxlength="64" pattern="[a-fA-F0-9]{64}" required></label></p>';
		echo '<p><label>' . esc_html__( 'Replacement bytes', 'amazing-security' ) . ' <input type="file" name="bytes" required></label></p>';
		echo '<p><label><input type="checkbox" name="confirm" value="1"> ' . esc_html__( 'I reviewed the path, the hash, and the uploaded bytes.', 'amazing-security' ) . '</label></p>';
		echo '<p><button class="button button-primary" type="submit">' . esc_html__( 'Replace file', 'amazing-security' ) . '</button></p></form>';
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
			'mode'   => __( 'Directory mode is now 0755.', 'amazing-security' ),
			'repair' => __( 'The file was replaced. The previous bytes are in a private temp backup.', 'amazing-security' ),
			'delete' => __( 'The file was moved out of the site into a private temp backup.', 'amazing-security' ),
		);
		if ( isset( $messages[ $code ] ) ) {
			echo '<div class="notice inline notice-success"><p>' . esc_html( $messages[ $code ] ) . '</p></div>';
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
		wp_safe_redirect( admin_url( 'admin.php?page=amsec-recovery&amsec_recovery=' . rawurlencode( $code ) ) );
		exit;
	}

	private static function upload(): string {
		$file = $_FILES['bytes'] ?? null; // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Nonce checked in guard. The upload is read with is_uploaded_file().
		if ( ! is_array( $file ) ) {
			wp_die( esc_html__( 'Upload a replacement file.', 'amazing-security' ), '', array( 'response' => 400 ) );
		}
		$error = isset( $file['error'] ) ? (int) $file['error'] : -1;
		$tmp   = isset( $file['tmp_name'] ) && is_string( $file['tmp_name'] ) ? $file['tmp_name'] : '';
		if ( UPLOAD_ERR_OK !== $error || ! is_uploaded_file( $tmp ) ) {
			wp_die( esc_html__( 'Upload a replacement file.', 'amazing-security' ), '', array( 'response' => 400 ) );
		}
		$size = filesize( $tmp );
		if ( false === $size || $size > DatabaseDump::MAX_BYTES ) {
			wp_die( esc_html__( 'The replacement is larger than 20 MB. The file was not written.', 'amazing-security' ), '', array( 'response' => 400 ) );
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Read the upload into memory. It is not moved into the plugin or uploads.
		$bytes = file_get_contents( $tmp );
		if ( ! is_string( $bytes ) ) {
			wp_die( esc_html__( 'The replacement could not be read. The file was not written.', 'amazing-security' ), '', array( 'response' => 400 ) );
		}
		return $bytes;
	}
}
