<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Activity;

defined( 'ABSPATH' ) || exit;

final class ActivityRenderer {
	/** @var array<int, string> */
	private array $names = array();

	public function render( array $rows, int $page, string $event, int $pages = 1, string $recordingForm = '' ): string {
		$html  = '<div class="wrap ironlatch-security-scanner-admin ironlatch-activity">';
		$html .= '<h1>' . esc_html__( 'Security activity', 'ironlatch-security-scanner' ) . '</h1>';
		$html .= '<p>' . esc_html__( 'Local history is best effort. A missing row does not mean nothing happened.', 'ironlatch-security-scanner' ) . '</p>';
		$html .= '<p>' . esc_html__( 'New rows are stored only after you turn recording on. They stay for 30 days. Visitor addresses and passwords are not stored.', 'ironlatch-security-scanner' ) . '</p>';
		$html .= $recordingForm;
		$html .= $this->filter( $event );
		if ( array() === $rows ) {
			$html .= '<p class="ironlatch-log-empty">' . esc_html__( 'No recorded events for this selection. This does not establish that no activity occurred.', 'ironlatch-security-scanner' ) . '</p>';
		} else {
			$html .= $this->days( $rows );
		}
		$html .= $this->pager( $page, $event, $pages );
		return $html . '</div>';
	}

	public static function label( string $event ): string {
		$names = array(
			'login_succeeded'          => __( 'Signed in', 'ironlatch-security-scanner' ),
			'login_failed'             => __( 'Sign-in failed', 'ironlatch-security-scanner' ),
			'login_rate_blocked'       => __( 'Sign-in limited', 'ironlatch-security-scanner' ),
			'user_created'             => __( 'Account created', 'ironlatch-security-scanner' ),
			'user_deleted'             => __( 'Account deleted', 'ironlatch-security-scanner' ),
			'user_role_changed'        => __( 'Role changed', 'ironlatch-security-scanner' ),
			'plugin_activated'         => __( 'Plugin activated', 'ironlatch-security-scanner' ),
			'plugin_deactivated'       => __( 'Plugin deactivated', 'ironlatch-security-scanner' ),
			'plugin_updated'           => __( 'Plugin updated', 'ironlatch-security-scanner' ),
			'theme_switched'           => __( 'Theme switched', 'ironlatch-security-scanner' ),
			'theme_updated'            => __( 'Theme updated', 'ironlatch-security-scanner' ),
			'security_setting_changed' => __( 'Security setting changed', 'ironlatch-security-scanner' ),
			'sessions_revoked'         => __( 'Sessions ended', 'ironlatch-security-scanner' ),
			'password_reset_required'  => __( 'Password reset required', 'ironlatch-security-scanner' ),
			'password_reset_cleared'   => __( 'Password reset cleared', 'ironlatch-security-scanner' ),
			'totp_policy_changed'      => __( 'Verification policy changed', 'ironlatch-security-scanner' ),
			'totp_grace_granted'       => __( 'Verification grace granted', 'ironlatch-security-scanner' ),
			'baseline_approved'        => __( 'Code reference approved', 'ironlatch-security-scanner' ),
			'bot_policy_changed'       => __( 'Comment check changed', 'ironlatch-security-scanner' ),
			'scanner_flagged'          => __( 'Scanner spotted', 'ironlatch-security-scanner' ),
			'scanner_blocked'          => __( 'Scanner blocked for an hour', 'ironlatch-security-scanner' ),
			'rate_limited'             => __( 'Rate limit reached', 'ironlatch-security-scanner' ),
			'rate_blocked'             => __( 'Rate limit block', 'ironlatch-security-scanner' ),
		);
		return $names[ $event ] ?? str_replace( '_', ' ', $event );
	}

	private function filter( string $event ): string {
		$html = '<form class="ironlatch-activity-filter" method="get"><input type="hidden" name="page" value="ironlatch-activity"><label for="ironlatch-event">' . esc_html__( 'Show', 'ironlatch-security-scanner' ) . '</label> <select id="ironlatch-event" name="event"><option value="">' . esc_html__( 'All events', 'ironlatch-security-scanner' ) . '</option>';
		foreach ( ActivityEvent::TYPES as $type ) {
			$html .= '<option value="' . esc_attr( $type ) . '"' . ( $type === $event ? ' selected' : '' ) . '>' . esc_html( self::label( $type ) ) . '</option>';
		}
		return $html . '</select> <button class="button">' . esc_html__( 'Filter', 'ironlatch-security-scanner' ) . '</button></form>';
	}

	private function days( array $rows ): string {
		$html   = '';
		$groups = array();
		foreach ( $rows as $row ) {
			$stamp            = (int) $row['created_at'];
			$key              = $this->clock( 'Y-m-d', $stamp );
			$groups[ $key ][] = $row;
		}
		foreach ( $groups as $group ) {
			$stamp = (int) $group[0]['created_at'];
			$html .= '<section class="ironlatch-log-day"><h2>' . esc_html( $this->clock( 'l, j F Y', $stamp ) ) . '</h2><ol class="ironlatch-log">';
			foreach ( $group as $row ) {
				$when  = (int) $row['created_at'];
				$html .= '<li><time datetime="' . esc_attr( gmdate( 'c', $when ) ) . '">' . esc_html( $this->clock( 'H:i', $when ) ) . '</time><p><strong>' . esc_html( self::label( (string) $row['event'] ) ) . '</strong><span>' . esc_html( $this->detail( $row ) ) . '</span></p></li>';
			}
			$html .= '</ol></section>';
		}
		return $html;
	}

	private function detail( array $row ): string {
		$event  = (string) $row['event'];
		$actor  = $this->account( (int) $row['actor_id'] );
		$person = $this->account( (int) $row['user_id'] );
		$target = $this->thing( (string) $row['target'] );
		$line   = '' !== $target ? $target : __( 'No extra detail', 'ironlatch-security-scanner' );

		if ( in_array( $event, array( 'login_succeeded', 'user_created', 'user_deleted', 'sessions_revoked', 'password_reset_required', 'password_reset_cleared', 'totp_grace_granted' ), true ) ) {
			$line = '' !== $person ? $person : __( 'Unknown account', 'ironlatch-security-scanner' );
		} elseif ( 'user_role_changed' === $event ) {
			$who  = '' !== $person ? $person : __( 'Unknown account', 'ironlatch-security-scanner' );
			$role = '' !== $target ? $target : __( 'another role', 'ironlatch-security-scanner' );
			$line = sprintf(
				/* translators: 1: account name, 2: role name. */
				__( '%1$s is now %2$s', 'ironlatch-security-scanner' ),
				$who,
				$role
			);
		} elseif ( in_array( $event, array( 'login_failed', 'login_rate_blocked' ), true ) ) {
			$line = __( 'No account was recorded', 'ironlatch-security-scanner' );
		}

		if ( '' === $actor ) {
			return $line;
		}
		return $line . ', ' . sprintf(
			/* translators: %s: account login. */
			__( 'by %s', 'ironlatch-security-scanner' ),
			$actor
		);
	}

	private function account( int $id ): string {
		if ( $id < 1 ) {
			return '';
		}
		if ( isset( $this->names[ $id ] ) ) {
			return $this->names[ $id ];
		}
		$name = sprintf( /* translators: %d: user ID of an account that cannot be read. */ __( 'Account %d', 'ironlatch-security-scanner' ), $id );
		if ( function_exists( 'get_userdata' ) ) {
			$user = get_userdata( $id );
			if ( is_object( $user ) && isset( $user->user_login ) && is_string( $user->user_login ) && '' !== $user->user_login ) {
				$login = $user->user_login;
				$shown = isset( $user->display_name ) && is_string( $user->display_name ) ? $user->display_name : '';
				$name  = '' !== $shown && 0 !== strcasecmp( $shown, $login ) ? $shown . ' (' . $login . ')' : $login;
			}
		}
		$this->names[ $id ] = $name;
		return $name;
	}

	private function thing( string $target ): string {
		$names = array(
			'ironlatch_login_rate_mode'              => __( 'Sign-in limit', 'ironlatch-security-scanner' ),
			'ironlatch_login_xmlrpc_disabled'        => __( 'XML-RPC sign-in', 'ironlatch-security-scanner' ),
			'ironlatch_alerts_enabled'               => __( 'Alert email', 'ironlatch-security-scanner' ),
			'ironlatch_digest_enabled'               => __( 'Weekly digest', 'ironlatch-security-scanner' ),
			'ironlatch_security_scanner_mcp_enabled' => __( 'Agent connection', 'ironlatch-security-scanner' ),
			'ironlatch_security_scanner_vulnerability_direct_enabled' => __( 'Direct vulnerability lookup', 'ironlatch-security-scanner' ),
			'ironlatch_security_scanner_kev_enabled' => __( 'CISA list of exploited holes', 'ironlatch-security-scanner' ),
		);
		if ( isset( $names[ $target ] ) ) {
			return $names[ $target ];
		}
		if ( str_contains( $target, '/' ) ) {
			$base = basename( dirname( $target ) );
			if ( '.' === $base || '' === $base ) {
				$base = basename( $target, '.php' );
			}
			$target = $base;
		}
		if ( 'ironlatch-security-scanner' === $target ) {
			return 'Ironlatch Security Scanner';
		}
		$words = str_replace( array( '-', '_' ), ' ', $target );
		return '' === $words ? '' : ucwords( $words );
	}

	private function clock( string $format, int $stamp ): string {
		if ( function_exists( 'wp_date' ) ) {
			return (string) wp_date( $format, $stamp );
		}
		return gmdate( $format, $stamp );
	}

	private function pager( int $page, string $event, int $pages ): string {
		if ( $pages < 2 ) {
			return '';
		}
		$page  = max( 1, min( $pages, $page ) );
		$html  = '<nav class="ironlatch-pager" aria-label="' . esc_attr__( 'Activity pages', 'ironlatch-security-scanner' ) . '">';
		$html .= $page > 1 ? '<a class="ironlatch-pager-nav" href="' . esc_url( $this->url( $page - 1, $event ) ) . '">' . esc_html__( 'Previous', 'ironlatch-security-scanner' ) . '</a>' : '<span class="ironlatch-pager-nav is-spacer" aria-hidden="true">' . esc_html__( 'Previous', 'ironlatch-security-scanner' ) . '</span>';
		$html .= '<span class="ironlatch-pager-label">' . esc_html(
			sprintf(
				/* translators: 1: current page, 2: page count. */
				__( 'Page %1$d of %2$d', 'ironlatch-security-scanner' ),
				$page,
				$pages
			)
		) . '</span>';
		$html .= $page < $pages ? '<a class="ironlatch-pager-nav" href="' . esc_url( $this->url( $page + 1, $event ) ) . '">' . esc_html__( 'Next', 'ironlatch-security-scanner' ) . '</a>' : '<span class="ironlatch-pager-nav is-spacer" aria-hidden="true">' . esc_html__( 'Next', 'ironlatch-security-scanner' ) . '</span>';
		return $html . '</nav>';
	}

	private function url( int $page, string $event ): string {
		return add_query_arg(
			array(
				'page'          => 'ironlatch-activity',
				'activity_page' => $page,
				'event'         => $event,
			),
			admin_url( 'admin.php' )
		);
	}
}
