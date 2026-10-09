<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

use AmazingPlugins\Security\FileScan\FileScanReport;
use AmazingPlugins\Security\FileScan\FileScanStep;
use AmazingPlugins\Security\FileScan\WordPressFileScanStore;
use AmazingPlugins\Security\Integrity\WordPressOptions;

final class FileScanReviewAction {
	public static function canNote( bool $hasCapability, bool $validNonce, bool $currentFinding ): bool {
		return $hasCapability && $validNonce && $currentFinding;
	}

	public static function validInput( string $findingId, string $note ): bool {
		return (bool) preg_match( '/^[a-f0-9]{32}$/D', $findingId ) && '' !== trim( $note ) && strlen( $note ) <= 500;
	}

	public static function hasCurrentFinding( ?FileScanStep $progress, ?FileScanReport $completed, string $id ): bool {
		$findings = null !== $progress ? $progress->cursor->findings : ( $completed?->findings ?? array() );
		foreach ( $findings as $finding ) {
			if ( is_string( $finding['id'] ?? null ) && hash_equals( $finding['id'], $id ) ) {
				return true;
			}
		}
		return false;
	}

	public function note(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You cannot review this file finding.', 'amazing-security' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'amsec_file_scan_note' );
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce was checked above.
		$id = isset( $_POST['finding_id'] ) && is_string( $_POST['finding_id'] ) ? sanitize_text_field( wp_unslash( $_POST['finding_id'] ) ) : '';
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce was checked above.
		$note      = isset( $_POST['note'] ) && is_string( $_POST['note'] ) ? sanitize_textarea_field( wp_unslash( $_POST['note'] ) ) : '';
		$store     = new WordPressFileScanStore( new WordPressOptions() );
		$progress  = $store->latestProgress();
		$completed = $store->latestCompleted();
		$current   = self::hasCurrentFinding( $progress, $completed, $id );
		if ( ! self::canNote( true, true, $current ) || ! self::validInput( $id, $note ) || ! $store->saveNote( $id, $note ) ) {
			wp_die( esc_html__( 'The finding or note is no longer valid.', 'amazing-security' ), '', array( 'response' => 400 ) );
		}
		wp_safe_redirect( admin_url( 'admin.php?page=amsec-file-checks#amsec-file-scan' ) );
		exit;
	}
}
