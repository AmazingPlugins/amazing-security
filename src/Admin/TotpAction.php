<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Access;

/** Enrollment retired — use a dedicated authenticator plugin. */
final class TotpAction {
	public static function canManage( int $userId, int $currentId, bool $hasCapability, bool $https ): bool {
		return Access::ownSecret( $currentId, $userId ) && $hasCapability && $https;
	}

	public function begin(): void {
		$this->retired();
	}

	public function confirm(): void {
		$this->retired();
	}

	public function disable(): void {
		$this->retired();
	}

	public function regenerate(): void {
		$this->retired();
	}

	private function retired(): void {
		wp_die( esc_html__( 'AmSec Security Scanner no longer enrolls authenticator apps. Use a dedicated two-factor plugin.', 'amsec-security-scanner' ), '', array( 'response' => 410 ) );
	}
}
