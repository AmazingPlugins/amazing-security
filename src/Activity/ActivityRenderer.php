<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Activity;

defined( 'ABSPATH' ) || exit;

final class ActivityRenderer {
	/** @var array<int, string> */
	private array $names = array();

	public function render( array $rows, int $page, string $event, int $pages = 1, string $recordingForm = '' ): string {
		$html  = '<div class="wrap amazing-security-admin amsec-activity">';
		$html .= '<h1>' . esc_html__( 'Security activity', 'amazing-security' ) . '</h1>';
		$html .= '<p>' . esc_html__( 'Local history is best effort. A missing row does not mean nothing happened.', 'amazing-security' ) . '</p>';
		$html .= '<p>' . esc_html__( 'New rows are stored only after you turn recording on. They stay for 30 days. Visitor addresses and passwords are not stored.', 'amazing-security' ) . '</p>';
		$html .= $recordingForm;
		$html .= $this->filter( $event );
		if ( array() === $rows ) {
			$html .= '<p class="amsec-log-empty">' . esc_html__( 'No recorded events for this selection. This does not establish that no activity occurred.', 'amazing-security' ) . '</p>';
		} else {
			$html .= $this->days( $rows );
		}
		$html .= $this->pager( $page, $event, $pages );
		return $html . '</div>';
	}

	public static function label( string $event ): string {
		$names = array(
			'login_succeeded'          => __( 'Signed in', 'amazing-security' ),
			'login_failed'             => __( 'Sign-in failed', 'amazing-security' ),
			'login_rate_blocked'       => __( 'Sign-in limited', 'amazing-security' ),
			'user_created'             => __( 'Account created', 'amazing-security' ),
			'user_deleted'             => __( 'Account deleted', 'amazing-security' ),
			'user_role_changed'        => __( 'Role changed', 'amazing-security' ),
			'plugin_activated'         => __( 'Plugin activated', 'amazing-security' ),
			'plugin_deactivated'       => __( 'Plugin deactivated', 'amazing-security' ),
			'plugin_updated'           => __( 'Plugin updated', 'amazing-security' ),
			'theme_switched'           => __( 'Theme switched', 'amazing-security' ),
			'theme_updated'            => __( 'Theme updated', 'amazing-security' ),
			'security_setting_changed' => __( 'Security setting changed', 'amazing-security' ),
			'sessions_revoked'         => __( 'Sessions ended', 'amazing-security' ),
			'password_reset_required'  => __( 'Password reset required', 'amazing-security' ),
			'password_reset_cleared'   => __( 'Password reset cleared', 'amazing-security' ),
			'totp_policy_changed'      => __( 'Verification policy changed', 'amazing-security' ),
			'totp_grace_granted'       => __( 'Verification grace granted', 'amazing-security' ),
			'baseline_approved'        => __( 'Code reference approved', 'amazing-security' ),
			'bot_policy_changed'       => __( 'Comment check changed', 'amazing-security' ),
		);
		return $names[ $event ] ?? str_replace( '_', ' ', $event );
	}

	private function filter( string $event ): string {
		$html = '<form class="amsec-activity-filter" method="get"><input type="hidden" name="page" value="amsec-activity"><label for="amsec-event">' . esc_html__( 'Show', 'amazing-security' ) . '</label> <select id="amsec-event" name="event"><option value="">' . esc_html__( 'All events', 'amazing-security' ) . '</option>';
		foreach ( ActivityEvent::TYPES as $type ) {
			$html .= '<option value="' . esc_attr( $type ) . '"' . ( $type === $event ? ' selected' : '' ) . '>' . esc_html( self::label( $type ) ) . '</option>';
		}
		return $html . '</select> <button class="button">' . esc_html__( 'Filter', 'amazing-security' ) . '</button></form>';
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
			$html .= '<section class="amsec-log-day"><h2>' . esc_html( $this->clock( 'l, j F Y', $stamp ) ) . '</h2><ol class="amsec-log">';
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
		$line   = '' !== $target ? $target : __( 'No extra detail', 'amazing-security' );

		if ( in_array( $event, array( 'login_succeeded', 'user_created', 'user_deleted', 'sessions_revoked', 'password_reset_required', 'password_reset_cleared', 'totp_grace_granted' ), true ) ) {
			$line = '' !== $person ? $person : __( 'Unknown account', 'amazing-security' );
		} elseif ( 'user_role_changed' === $event ) {
			$who  = '' !== $person ? $person : __( 'Unknown account', 'amazing-security' );
			$role = '' !== $target ? $target : __( 'another role', 'amazing-security' );
			$line = sprintf(
				/* translators: 1: account name, 2: role name. */
				__( '%1$s is now %2$s', 'amazing-security' ),
				$who,
				$role
			);
		} elseif ( in_array( $event, array( 'login_failed', 'login_rate_blocked' ), true ) ) {
			$line = __( 'No account was recorded', 'amazing-security' );
		}

		if ( '' === $actor ) {
			return $line;
		}
		return $line . ', ' . sprintf(
			/* translators: %s: account login. */
			__( 'by %s', 'amazing-security' ),
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
		$name = sprintf( /* translators: %d: user ID of an account that cannot be read. */ __( 'Account %d', 'amazing-security' ), $id );
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
			'amsec_login_rate_mode'        => __( 'Sign-in limit', 'amazing-security' ),
			'amsec_login_xmlrpc_disabled'  => __( 'XML-RPC sign-in', 'amazing-security' ),
			'amsec_alerts_enabled'         => __( 'Alert email', 'amazing-security' ),
			'amsec_digest_enabled'         => __( 'Weekly digest', 'amazing-security' ),
			'amazing_security_mcp_enabled' => __( 'Assistant connection', 'amazing-security' ),
			'amazing_security_vulnerability_direct_enabled' => __( 'Direct vulnerability lookup', 'amazing-security' ),
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
		$html  = '<nav class="amsec-pager" aria-label="' . esc_attr__( 'Activity pages', 'amazing-security' ) . '">';
		$html .= $page > 1 ? '<a class="amsec-pager-nav" href="' . esc_url( $this->url( $page - 1, $event ) ) . '">' . esc_html__( 'Previous', 'amazing-security' ) . '</a>' : '<span class="amsec-pager-nav is-spacer" aria-hidden="true">' . esc_html__( 'Previous', 'amazing-security' ) . '</span>';
		$html .= '<span class="amsec-pager-label">' . esc_html(
			sprintf(
				/* translators: 1: current page, 2: page count. */
				__( 'Page %1$d of %2$d', 'amazing-security' ),
				$page,
				$pages
			)
		) . '</span>';
		$html .= $page < $pages ? '<a class="amsec-pager-nav" href="' . esc_url( $this->url( $page + 1, $event ) ) . '">' . esc_html__( 'Next', 'amazing-security' ) . '</a>' : '<span class="amsec-pager-nav is-spacer" aria-hidden="true">' . esc_html__( 'Next', 'amazing-security' ) . '</span>';
		return $html . '</nav>';
	}

	private function url( int $page, string $event ): string {
		return add_query_arg(
			array(
				'page'          => 'amsec-activity',
				'activity_page' => $page,
				'event'         => $event,
			),
			admin_url( 'admin.php' )
		);
	}
}
