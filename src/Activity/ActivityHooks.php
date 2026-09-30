<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Activity;

final class ActivityHooks {
	private int $recorded = 0;

	public function __construct( private readonly ActivityRepository $repository ) {}

	public function register(): void {
		add_action(
			'wp_login',
			function ( string $login, \WP_User $user ): void {
				$this->record( 'login_succeeded', $user->ID );
			},
			10,
			2
		);
		add_action(
			'wp_login_failed',
			function (): void {
				$this->record( 'login_failed' );
			}
		);
		add_action(
			'user_register',
			function ( int $id ): void {
				$this->record( 'user_created', $id );
			}
		);
		add_action(
			'deleted_user',
			function ( int $id ): void {
				$this->record( 'user_deleted', $id );
			}
		);
		add_action(
			'set_user_role',
			function ( int $id, string $role ): void {
				$this->record( 'user_role_changed', $id, $role );
			},
			10,
			2
		);
		add_action(
			'add_user_role',
			function ( int $id, string $role ): void {
				$this->record( 'user_role_changed', $id, $role );
			},
			10,
			2
		);
		add_action(
			'remove_user_role',
			function ( int $id, string $role ): void {
				$this->record( 'user_role_changed', $id, $role );
			},
			10,
			2
		);
		add_action(
			'activated_plugin',
			function ( string $plugin ): void {
				$this->record( 'plugin_activated', 0, $plugin );
			}
		);
		add_action(
			'deactivated_plugin',
			function ( string $plugin ): void {
				$this->record( 'plugin_deactivated', 0, $plugin );
			}
		);
		add_action(
			'switch_theme',
			function ( string $name, \WP_Theme $theme ): void {
				$this->record( 'theme_switched', 0, $theme->get_stylesheet() );
			},
			10,
			2
		);
		add_action( 'upgrader_process_complete', array( $this, 'upgraded' ), 10, 2 );
		add_action( 'updated_option', array( $this, 'optionChanged' ), 10, 1 );
		add_action( 'added_option', array( $this, 'optionChanged' ), 10, 1 );
		add_action( 'amsec_option_written', array( $this, 'optionChanged' ), 10, 1 );
	}

	public function upgraded( object $upgrader, array $extra ): void {
		if ( 'update' !== ( $extra['action'] ?? '' ) || ! in_array( $extra['type'] ?? '', array( 'plugin', 'theme' ), true ) ) {
			return;
		}
		$kind  = $extra['type'];
		$items = $extra[ $kind . 's' ] ?? array( $extra[ $kind ] ?? '' );
		if ( ! is_array( $items ) || 1 !== count( $items ) || ! empty( $extra['bulk'] ) ) {
			return;
		}
		foreach ( $items as $item ) {
			// WordPress emits the completion hook for failed bulk items too. Record only success.
			$result = isset( $upgrader->result ) ? $upgrader->result : null;
			if ( is_array( $result ) && is_string( $item ) && '' !== $item ) {
				$this->record( $kind . '_updated', 0, $item );
			}
		}
	}

	public function optionChanged( string $name ): void {
		if ( in_array( $name, array( 'amsec_login_rate_mode', 'amsec_login_xmlrpc_disabled', 'amsec_alerts_enabled', 'amazing_security_mcp_enabled', 'amazing_security_vulnerability_direct_enabled' ), true ) ) {
			$this->record( 'security_setting_changed', 0, $name );
		}
	}

	public function record( string $event, int $user = 0, string $target = '' ): void {
		if ( $this->recorded >= 20 || '1' !== get_option( 'amsec_activity_schema_version' ) ) {
			return;
		}
		++$this->recorded;
		try {
			$this->repository->append( new ActivityEvent( $event, 'login_failed' === $event ? 0 : get_current_user_id(), $user, $target, time() ) );
		} catch ( \Throwable ) {
			// Logging failure must not interrupt authentication, checkout or updates.
			return;
		}
	}
}
