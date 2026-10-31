<?php

// Test-only route for a disposable WordPress container. Never package this file.
add_action(
	'rest_api_init',
	static function (): void {
		register_rest_route(
			'amsec-test/v1',
			'/approve',
			array(
				'methods' => 'POST',
				'permission_callback' => static fn(): bool => current_user_can( 'manage_options' ),
				'callback' => static function (): never {
					( new AmazingPlugins\Security\Admin\FixApprovalAction() )->handle();
				},
			)
		);
	}
);
