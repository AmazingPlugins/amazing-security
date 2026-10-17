<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Free\TrafficGuard;

defined( 'ABSPATH' ) || exit;

/** Boots on plugins_loaded and enforces controls on init. */
final class Module {
	public static function boot(): void {
		$guard = new Guard();
		add_action( 'init', array( $guard, 'enforce' ), 0 );
		add_action( 'admin_menu', array( new Page(), 'register' ) );
		add_action( 'admin_post_amsec_traffic_guard', array( new Page(), 'save' ) );
		add_action( 'update_option_' . Options::LIVE, array( Guard::class, 'syncFromUpdate' ), 10, 2 );
		add_action( 'add_option_' . Options::LIVE, array( Guard::class, 'syncFromAdd' ), 10, 2 );
	}
}
