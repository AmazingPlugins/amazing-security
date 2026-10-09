<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Sessions;

final class SessionPage {
	public function register(): void {
		// Empty parent keeps this off the side menu. Capability is read so the account owner can open it. render() still allows only an administrator or that owner.
		$hook = add_submenu_page( '', __( 'Account sessions', 'amazing-security' ), __( 'Sessions', 'amazing-security' ), 'read', 'amsec-sessions', array( $this, 'render' ) );
		if ( is_string( $hook ) ) {
			add_action(
				'load-' . $hook,
				static function (): void {
					global $title;
					if ( ! is_string( $title ) || '' === $title ) {
						// phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- An empty menu parent leaves this null, and admin-header.php passes it to strip_tags().
						$title = __( 'Account sessions', 'amazing-security' );
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
		echo '<h2>' . esc_html__( 'Sessions', 'amazing-security' ) . '</h2><p>' . esc_html__( 'Only you and an administrator can open this page.', 'amazing-security' ) . ' <a href="' . esc_url( $url ) . '">' . esc_html__( 'View page', 'amazing-security' ) . '</a></p>';
	}

	public function render(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only account selection with permission checks.
		$id = isset( $_GET['user_id'] ) && is_scalar( $_GET['user_id'] ) ? absint( wp_unslash( (string) $_GET['user_id'] ) ) : get_current_user_id();
		if ( 1 > $id || ! get_userdata( $id ) || ! SessionPolicy::canView( current_user_can( 'manage_options' ), get_current_user_id(), $id ) ) {
			wp_die( esc_html__( 'You cannot view this session page.', 'amazing-security' ), '', array( 'response' => 403 ) );
		}
		$administrator = current_user_can( 'manage_options' );
		try {
			$rows = $this->rows( $id );
		} catch ( \Throwable ) {
			echo '<div class="wrap amazing-security-admin"><div class="notice notice-error"><p>Session information is unavailable.</p></div></div>';
			return;
		}
		if ( $this->wantsDetail() ) {
			$this->detail( $rows, $administrator );
			return;
		}
		if ( ! $administrator ) {
			echo '<div class="wrap amazing-security-admin"><h1>Your sessions</h1><p>Only you and an administrator can open this page.</p>';
			$this->lines( $id, $rows );
			echo '</div>';
			return;
		}
		$accounts = $this->accountOptions( $id );
		echo '<div class="wrap amazing-security-admin"><h1>Account sessions</h1><p>Pick an account. Ending a session signs that browser out. It cannot be undone. A new sign-in can start another session. An application password can be removed on its own.</p><form method="get"><input type="hidden" name="page" value="amsec-sessions"><label for="amsec-session-user">Account</label> <select id="amsec-session-user" name="user_id">';
		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- accountOptions() escapes each login and display name.
		echo $accounts;
		echo '</select> <button class="button">View account</button></form>';
		$this->lines( $id, $rows );
		$this->applicationPasswords( $id );
		echo '<h2>Revoke sessions</h2><p>' . ( get_current_user_id() === $id ? 'Your current session will be kept. Your other sessions will be revoked.' : 'All existing sessions for this selected account will be revoked.' ) . '</p>';
		if ( ! is_ssl() ) {
			echo '<p>Open this page over HTTPS to approve session revocation.</p></div>';
			return;
		}
		echo '<form action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" method="post"><input type="hidden" name="action" value="amsec_sessions_revoke"><input type="hidden" name="user_id" value="' . esc_attr( (string) $id ) . '">';
		wp_nonce_field( 'amsec_sessions_revoke_' . $id );
		echo '<p><label for="amsec-session-password">Your password</label> <input id="amsec-session-password" type="password" name="password" autocomplete="current-password" required maxlength="1024"></p><p><label><input type="checkbox" name="confirm" value="1" required> I understand that revocation cannot be undone.</label></p>';
		submit_button( __( 'Revoke these sessions', 'amazing-security' ), 'secondary' );
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
			echo '<p>No sessions returned by the account session manager.</p>';
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
				$parts[] = 'This browser';
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
			echo '<a href="' . esc_url( $url ) . '">' . esc_html__( 'View page', 'amazing-security' ) . '<span class="screen-reader-text">: ' . esc_html( $title ) . '</span></a>';
			echo '</li>';
		}
		echo '</ul>';
	}

	/** @param array<int, array{login: int, expiration: int, ip: string, ua: string, current: bool}> $rows */
	private function detail( array $rows, bool $administrator ): void {
		$row  = SessionPolicy::rowFor( $rows, $this->requestedRef() );
		$back = $administrator ? admin_url( 'admin.php?page=amsec-accounts#sessions' ) : admin_url( 'admin.php?page=amsec-sessions' );
		echo '<div class="wrap amazing-security-admin"><p class="amsec-session-back"><a href="' . esc_url( $back ) . '">Back to sessions</a></p>';
		if ( null === $row ) {
			echo '<h1>Session</h1><p>This session is no longer available.</p></div>';
			return;
		}
		$browser  = SessionDetail::browser( $row['ua'] );
		$computer = SessionDetail::computer( $row['ua'] );
		$place    = SessionDetail::place( $row['ip'] );
		$title    = $this->sessionTitle( $browser, $computer );
		echo '<article class="amsec-session' . ( $row['current'] ? ' is-current' : '' ) . '">';
		echo '<p class="amsec-session-kicker"><span class="dashicons ' . esc_attr( SessionDetail::icon( $computer ) ) . '" aria-hidden="true"></span> ';
		echo esc_html( $row['current'] ? 'This browser' : 'Session' ) . '</p>';
		echo '<h1>' . esc_html( $title ) . '</h1><dl>';
		$this->fact( 'Browser', '' !== $browser ? $browser : 'Not recorded' );
		$this->fact( 'Computer', '' !== $computer ? $computer : 'Not recorded' );
		$this->fact( 'Location', '' !== $place ? $place : 'Not recorded' );
		if ( '' !== $row['ip'] && $place !== $row['ip'] ) {
			$this->fact( 'Address', $row['ip'] );
		}
		$this->fact( 'Signed in', $this->when( $row['login'] ) );
		$this->fact( 'Expires', $this->when( $row['expiration'] ) );
		echo '</dl>';
		if ( '' !== $row['ua'] ) {
			echo '<h2>Browser details</h2><p class="amsec-session-agent">' . esc_html( $row['ua'] ) . '</p>';
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
		return 'Session';
	}

	private function fact( string $label, string $value ): void {
		echo '<div><dt>' . esc_html( $label ) . '</dt><dd>' . esc_html( $value ) . '</dd></div>';
	}

	private function when( int $stamp ): string {
		if ( $stamp < 1 ) {
			return 'Not recorded';
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
		echo '<h2>Application passwords</h2>';
		if ( ! class_exists( \WP_Application_Passwords::class ) ) {
			echo '<p>Application passwords are unavailable on this site.</p>';
			return;
		}
		$stored = \WP_Application_Passwords::get_user_application_passwords( $id );
		$rows   = ApplicationPasswordList::rows( is_array( $stored ) ? $stored : array() );
		if ( array() === $rows ) {
			echo '<p>No application passwords are stored for this account.</p>';
			return;
		}
		echo '<table class="widefat striped"><caption>Saved application passwords. The password itself is not shown.</caption><thead><tr><th scope="col">Name</th><th scope="col">Created UTC</th><th scope="col">Revoke</th></tr></thead><tbody>';
		foreach ( $rows as $row ) {
			echo '<tr><td>' . esc_html( $row['name'] ) . '</td><td>' . esc_html( $row['created'] > 0 ? gmdate( 'Y-m-d H:i:s', $row['created'] ) : 'Unknown' ) . '</td><td>';
			if ( is_ssl() ) {
				echo '<form action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" method="post"><input type="hidden" name="action" value="amsec_sessions_revoke"><input type="hidden" name="operation" value="revoke-application-password"><input type="hidden" name="user_id" value="' . esc_attr( (string) $id ) . '"><input type="hidden" name="uuid" value="' . esc_attr( $row['uuid'] ) . '">';
				wp_nonce_field( 'amsec_sessions_revoke_' . $id );
				echo '<p><label>Your password <input type="password" name="password" autocomplete="current-password" required maxlength="1024"></label></p><p><label><input type="checkbox" name="confirm" value="1" required> I understand that this application password will be removed.</label></p>';
				submit_button( __( 'Revoke this application password', 'amazing-security' ), 'secondary', 'submit', false );
				echo '</form>';
			} else {
				esc_html_e( 'Open this page over HTTPS to revoke it.', 'amazing-security' );
			}
			echo '</td></tr>';
		}
		echo '</tbody></table>';
	}
}
