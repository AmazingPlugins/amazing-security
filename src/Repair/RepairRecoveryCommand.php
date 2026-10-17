<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Repair;

defined( 'ABSPATH' ) || exit;

final class RepairRecoveryCommand {
	/**
	 * Roll back a verified plugin file repair while its replacement hash still matches.
	 *
	 * ## OPTIONS
	 *
	 * <finding-id>
	 * : The 32-character finding ID shown in the repair review page.
	 */
	public function rollback( array $args ): void {
		$id = $args[0] ?? '';
		if ( ! is_string( $id ) || ! preg_match( '/^[a-f0-9]{32}$/D', $id ) || ! ( new WordPressPluginRepair() )->rollback( $id ) ) {
			\WP_CLI::error( 'Rollback refused: receipt, backup, installed plugin, or current hash did not match.' );
		}
		\WP_CLI::success( 'Verified plugin file backup restored.' );
	}

	/**
	 * Restore a retained backup after replacement verification failed.
	 *
	 * ## OPTIONS
	 *
	 * <finding-id>
	 * : The finding ID shown in the repair review page.
	 *
	 * --current-sha256=<hash>
	 * : SHA-256 of the file you inspected on disk immediately before recovery.
	 *
	 * --confirm
	 * : Confirm replacing that exact current file with the retained backup.
	 */
	public function recover( array $args, array $assocArgs ): void {
		$id   = $args[0] ?? '';
		$hash = $assocArgs['current-sha256'] ?? '';
		if ( ! isset( $assocArgs['confirm'] ) || ! is_string( $id ) || ! is_string( $hash ) || ! preg_match( '/^[a-f0-9]{32}$/D', $id ) || ! ( new WordPressPluginRepair() )->recover( $id, $hash ) ) {
			\WP_CLI::error( 'Recovery refused: confirmation, retained backup, installed plugin, or current file hash did not match.' );
		}
		\WP_CLI::success( 'Retained plugin file backup restored.' );
	}
}
