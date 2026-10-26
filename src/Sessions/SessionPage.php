<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Sessions;

defined( 'ABSPATH' ) || exit;

final class SessionPage {
	public function register(): void {
		// Empty parent keeps this off the side menu. Capability is read so the account owner can open it. render() still allows only an administrator or that owner.
		$hook = add_submenu_page( '', __( 'Account sessions', 'amazing-security-scanner' ), __( 'Sessions', 'amazing-security-scanner' ), 'read', 'amsec-sessions', array( $this, 'render' ) );
		if ( is_string( $hook ) ) {
			add_action(
				'load-' . $hook,
				static function (): void {
					global $title;
					if ( ! is_string( $title ) || '' === $title ) {
						// phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- An empty menu parent leaves this null, and admin-header.php passes it to strip_tags().
						$title = __( 'Account sessions', 'amazing-security-scanner' );
					}
				}
			);
		}
		add_action( 'show_user_profile', array( $this, 'profileLink' ) );
		add_action( 'edit_user_profile', array( $this, 'profileLink' ) );
	}

	public function profileLink( \WP_User $user ): void {
		if ( ! SessionPolicy::canView( current_user_can( 'manage_options' ), get_current_user_id(), (int) $user->ID ) ) {
			return;
		}
		$url = add_query_arg(
			array(
				'page'    => 'amsec-sessions',
				'user_id' => (int) $user->ID,
			),
			admin_url( 'admin.php' )
		);
		echo '<h2>' . esc_html__( 'Sessions', 'amazing-security-scanner' ) . '</h2><p>' . esc_html__( 'Only you and an administrator can open this page.', 'amazing-security-scanner' ) . ' <a href="' . esc_url( $url ) . '">' . esc_html__( 'View page', 'amazing-security-scanner' ) . '</a></p>';
	}

	public function render(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only account selection with permission checks.
		$id = isset( $_GET['user_id'] ) && is_scalar( $_GET['user_id'] ) ? absint( wp_unslash( (string) $_GET['user_id'] ) ) : get_current_user_id();
		if ( 1 > $id || ! get_userdata( $id ) || ! SessionPolicy::canView( current_user_can( 'manage_options' ), get_current_user_id(), $id ) ) {
			wp_die( esc_html__( 'You cannot view this session page.', 'amazing-security-scanner' ), '', array( 'response' => 403 ) );
		}
		$administrator = current_user_can( 'manage_options' );
		try {
			$rows = $this->rows( $id );
		} catch ( \Throwable ) {
			echo '<div class="wrap amazing-security-admin"><div class="notice notice-error"><p>' . esc_html__( 'Session information is unavailable.', 'amazing-security-scanner' ) . '</p></div></div>';
			return;
		}
		if ( $this->wantsDetail() ) {
			$this->detail( $rows, $administrator );
			return;
		}
		if ( ! $administrator ) {
			echo '<div class="wrap amazing-security-admin"><h1>' . esc_html__( 'Your sessions', 'amazing-security-scanner' ) . '</h1><p>' . esc_html__( 'Only you and an administrator can open this page.', 'amazing-security-scanner' ) . '</p>';
			$this->lines( $id, $rows );
			echo '</div>';
			return;
		}
		$accounts = $this->accountOptions( $id );
		echo '<div class="wrap amazing-security-admin"><h1>' . esc_html__( 'Account sessions', 'amazing-security-scanner' ) . '</h1><p>' . esc_html__( 'Pick an account. Ending a session signs that browser out. It cannot be undone. A new sign-in can start another session. An application password can be removed on its own.', 'amazing-security-scanner' ) . '</p><form method="get" action="#sessions"><input type="hidden" name="page" value="amsec-accounts"><label for="amsec-session-user">' . esc_html__( 'Account', 'amazing-security-scanner' ) . '</label> <select id="amsec-session-user" name="user_id">';
		echo wp_kses( $accounts, \AmazingPlugins\Security\Admin\AdminHtml::allowed() );
		echo '</select> <button class="button">' . esc_html__( 'View account', 'amazing-security-scanner' ) . '</button></form>';
		$this->lines( $id, $rows );
		$this->applicationPasswords( $id );
		echo '<h2>' . esc_html__( 'Revoke sessions', 'amazing-security-scanner' ) . '</h2><p>' . ( get_current_user_id() === $id ? esc_html__( 'Your current session will be kept. Your other sessions will be revoked.', 'amazing-security-scanner' ) : esc_html__( 'All existing sessions for this selected account will be revoked.', 'amazing-security-scanner' ) ) . '</p>';
		if ( ! is_ssl() ) {
			echo '<p>' . esc_html__( 'Open this page over HTTPS to approve session revocation.', 'amazing-security-scanner' ) . '</p></div>';
			return;
		}
		echo '<form action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" method="post"><input type="hidden" name="action" value="amsec_sessions_revoke"><input type="hidden" name="user_id" value="' . esc_attr( (string) $id ) . '">';
		wp_nonce_field( 'amsec_sessions_revoke_' . $id );
		echo '<p><label for="amsec-session-password">' . esc_html__( 'Your password', 'amazing-security-scanner' ) . '</label> <input id="amsec-session-password" type="password" name="password" autocomplete="current-password" required maxlength="1024"></p><p><label><input type="checkbox" name="confirm" value="1" required> ' . esc_html__( 'I understand that revocation cannot be undone.', 'amazing-security-scanner' ) . '</label></p>';
		submit_button( __( 'Revoke these sessions', 'amazing-security-scanner' ), 'secondary' );
		echo '</form></div>';
	}

	/** @return array<int, array{login: int, expiration: int, ip: string, ua: string, current: bool}> */
	private function rows( int $id ): array {
		$manager = \WP_Session_Tokens::get_instance( $id );
		$live    = array();
		if ( function_exists( 'wp_get_session_token' ) && get_current_user_id() === $id ) {
			$token = (string) wp_get_session_token();
			$found = '' !== $token ? $manager->get( $token ) : null;
			$live  = is_array( $found ) ? $found : array();
		}
		return SessionPolicy::safeRows( $manager->get_all(), $live );
	}

	private function wantsDetail(): bool {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only screen choice.
		$page = isset( $_GET['page'] ) && is_scalar( $_GET['page'] ) ? sanitize_key( (string) wp_unslash( $_GET['page'] ) ) : '';
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only screen choice.
		return 'amsec-sessions' === $page && isset( $_GET['session'] );
	}

	private function requestedRef(): string {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only session choice. The value is a display hash, not a session token.
		$raw = isset( $_GET['session'] ) && is_scalar( $_GET['session'] ) ? sanitize_text_field( wp_unslash( $_GET['session'] ) ) : '';
		return 1 === preg_match( '/\A[a-f0-9]{16}\z/', $raw ) ? $raw : '';
	}

	/** @param array<int, array{login: int, expiration: int, ip: string, ua: string, current: bool}> $rows */
	private function lines( int $id, array $rows ): void {
		if ( array() === $rows ) {
			echo '<p>' . esc_html__( 'No sessions returned by the account session manager.', 'amazing-security-scanner' ) . '</p>';
			return;
		}
		echo '<ul class="amsec-session-lines">';
		foreach ( $rows as $row ) {
			$browser  = SessionDetail::browser( $row['ua'] );
			$computer = SessionDetail::computer( $row['ua'] );
			$title    = $this->sessionTitle( $browser, $computer );
			$place    = SessionDetail::place( $row['ip'] );
			$parts    = array();
			if ( $row['current'] ) {
				$parts[] = __( 'This browser', 'amazing-security-scanner' );
			}
			$parts[] = $title;
			if ( '' !== $place ) {
				$parts[] = $place;
			}
			$parts[] = $this->when( $row['login'] );
			$url     = add_query_arg(
				array(
					'page'    => 'amsec-sessions',
					'user_id' => $id,
					'session' => SessionPolicy::ref( $row ),
				),
				admin_url( 'admin.php' )
			);
			echo '<li' . ( $row['current'] ? ' class="is-current"' : '' ) . '>';
			echo '<span class="dashicons ' . esc_attr( SessionDetail::icon( $computer ) ) . '" aria-hidden="true"></span>';
			echo '<span class="amsec-session-summary">' . esc_html( implode( ' · ', $parts ) ) . '</span>';
			echo '<a href="' . esc_url( $url ) . '">' . esc_html__( 'View page', 'amazing-security-scanner' ) . '<span class="screen-reader-text">: ' . esc_html( $title ) . '</span></a>';
			echo '</li>';
		}
		echo '</ul>';
	}

	/** @param array<int, array{login: int, expiration: int, ip: string, ua: string, current: bool}> $rows */
	private function detail( array $rows, bool $administrator ): void {
		$row  = SessionPolicy::rowFor( $rows, $this->requestedRef() );
		$back = $administrator ? admin_url( 'admin.php?page=amsec-accounts#sessions' ) : admin_url( 'admin.php?page=amsec-sessions' );
		echo '<div class="wrap amazing-security-admin"><p class="amsec-session-back"><a href="' . esc_url( $back ) . '">' . esc_html__( 'Back to sessions', 'amazing-security-scanner' ) . '</a></p>';
		if ( null === $row ) {
			echo '<h1>' . esc_html__( 'Session', 'amazing-security-scanner' ) . '</h1><p>' . esc_html__( 'This session is no longer available.', 'amazing-security-scanner' ) . '</p></div>';
			return;
		}
		$browser  = SessionDetail::browser( $row['ua'] );
		$computer = SessionDetail::computer( $row['ua'] );
		$place    = SessionDetail::place( $row['ip'] );
		$title    = $this->sessionTitle( $browser, $computer );
		echo '<article class="amsec-session' . ( $row['current'] ? ' is-current' : '' ) . '">';
		echo '<p class="amsec-session-kicker"><span class="dashicons ' . esc_attr( SessionDetail::icon( $computer ) ) . '" aria-hidden="true"></span> ';
		echo esc_html( $row['current'] ? __( 'This browser', 'amazing-security-scanner' ) : __( 'Session', 'amazing-security-scanner' ) ) . '</p>';
		echo '<h1>' . esc_html( $title ) . '</h1><dl>';
		$this->fact( __( 'Browser', 'amazing-security-scanner' ), '' !== $browser ? $browser : __( 'Not recorded', 'amazing-security-scanner' ) );
		$this->fact( __( 'Computer', 'amazing-security-scanner' ), '' !== $computer ? $computer : __( 'Not recorded', 'amazing-security-scanner' ) );
		$this->fact( __( 'Location', 'amazing-security-scanner' ), '' !== $place ? $place : __( 'Not recorded', 'amazing-security-scanner' ) );
		if ( '' !== $row['ip'] && $place !== $row['ip'] ) {
			$this->fact( __( 'Address', 'amazing-security-scanner' ), $row['ip'] );
		}
		$this->fact( __( 'Signed in', 'amazing-security-scanner' ), $this->when( $row['login'] ) );
		$this->fact( __( 'Expires', 'amazing-security-scanner' ), $this->when( $row['expiration'] ) );
		echo '</dl>';
		if ( '' !== $row['ua'] ) {
			echo '<h2>' . esc_html__( 'Browser details', 'amazing-security-scanner' ) . '</h2><p class="amsec-session-agent">' . esc_html( $row['ua'] ) . '</p>';
		}
		echo '</article></div>';
	}

	private function sessionTitle( string $browser, string $computer ): string {
		if ( '' !== $browser && '' !== $computer ) {
			return $browser . ' on ' . $computer;
		}
		if ( '' !== $browser ) {
			return $browser;
		}
		if ( '' !== $computer ) {
			return $computer;
		}
		return __( 'Session', 'amazing-security-scanner' );
	}

	private function fact( string $label, string $value ): void {
		echo '<div><dt>' . esc_html( $label ) . '</dt><dd>' . esc_html( $value ) . '</dd></div>';
	}

	private function when( int $stamp ): string {
		if ( $stamp < 1 ) {
			return __( 'Not recorded', 'amazing-security-scanner' );
		}
		if ( function_exists( 'wp_date' ) ) {
			return wp_date( 'j M Y, H:i', $stamp );
		}
		return gmdate( 'Y-m-d H:i:s', $stamp );
	}

	private function accountOptions( int $selected ): string {
		$users = get_users(
			array(
				'role__in' => array( 'administrator', 'editor' ),
				'number'   => 50,
				'orderby'  => 'display_name',
				'order'    => 'ASC',
			)
		);
		$html  = '';
		$seen  = array();
		foreach ( $users as $user ) {
			if ( ! $user instanceof \WP_User || ! current_user_can( 'edit_user', $user->ID ) ) {
				continue;
			}
			$seen[ $user->ID ] = true;
			$html             .= '<option value="' . esc_attr( (string) $user->ID ) . '"' . selected( $selected, $user->ID, false ) . '>' . esc_html( \AmazingPlugins\Security\Admin\AccountChoice::label( $user->user_login, $user->display_name ) ) . '</option>';
		}
		if ( ! isset( $seen[ $selected ] ) ) {
			$current = get_userdata( $selected );
			if ( $current instanceof \WP_User ) {
				$html = '<option value="' . esc_attr( (string) $current->ID ) . '" selected>' . esc_html( \AmazingPlugins\Security\Admin\AccountChoice::label( $current->user_login, $current->display_name ) ) . '</option>' . $html;
			}
		}
		return '' !== $html ? $html : '<option value="' . esc_attr( (string) $selected ) . '">' . esc_html( (string) $selected ) . '</option>';
	}

	private function applicationPasswords( int $id ): void {
		echo '<h2>' . esc_html__( 'Application passwords', 'amazing-security-scanner' ) . '</h2>';
		if ( ! class_exists( \WP_Application_Passwords::class ) ) {
			echo '<p>' . esc_html__( 'Application passwords are unavailable on this site.', 'amazing-security-scanner' ) . '</p>';
			return;
		}
		$stored = \WP_Application_Passwords::get_user_application_passwords( $id );
		$rows   = ApplicationPasswordList::rows( is_array( $stored ) ? $stored : array() );
		if ( array() === $rows ) {
			echo '<p>' . esc_html__( 'No application passwords are stored for this account.', 'amazing-security-scanner' ) . '</p>';
			return;
		}
		echo '<table class="widefat striped"><caption>' . esc_html__( 'Saved application passwords. The password itself is not shown.', 'amazing-security-scanner' ) . '</caption><thead><tr><th scope="col">' . esc_html__( 'Name', 'amazing-security-scanner' ) . '</th><th scope="col">' . esc_html__( 'Created UTC', 'amazing-security-scanner' ) . '</th><th scope="col">' . esc_html__( 'Revoke', 'amazing-security-scanner' ) . '</th></tr></thead><tbody>';
		foreach ( $rows as $row ) {
			echo '<tr><td>' . esc_html( $row['name'] ) . '</td><td>' . esc_html( $row['created'] > 0 ? gmdate( 'Y-m-d H:i:s', $row['created'] ) : __( 'Unknown', 'amazing-security-scanner' ) ) . '</td><td>';
			if ( is_ssl() ) {
				echo '<form action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" method="post"><input type="hidden" name="action" value="amsec_sessions_revoke"><input type="hidden" name="operation" value="revoke-application-password"><input type="hidden" name="user_id" value="' . esc_attr( (string) $id ) . '"><input type="hidden" name="uuid" value="' . esc_attr( $row['uuid'] ) . '">';
				wp_nonce_field( 'amsec_sessions_revoke_' . $id );
				echo '<p><label>' . esc_html__( 'Your password', 'amazing-security-scanner' ) . ' <input type="password" name="password" autocomplete="current-password" required maxlength="1024"></label></p><p><label><input type="checkbox" name="confirm" value="1" required> ' . esc_html__( 'I understand that this application password will be removed.', 'amazing-security-scanner' ) . '</label></p>';
				submit_button( __( 'Revoke this application password', 'amazing-security-scanner' ), 'secondary', 'submit', false );
				echo '</form>';
			} else {
				esc_html_e( 'Open this page over HTTPS to revoke it.', 'amazing-security-scanner' );
			}
			echo '</td></tr>';
		}
		echo '</tbody></table>';
	}
}
