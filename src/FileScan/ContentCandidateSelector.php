<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\FileScan;

defined( 'ABSPATH' ) || exit;

final class ContentCandidateSelector {
	public function eligible( FileScanTarget $target, string $relativePath, ?string $observedSha256, bool $extra = false ): bool {
		if ( ! preg_match( '/\.(?:php|phtml|php[0-9]+|pht)$/iD', $relativePath ) ) {
			return false;
		}
		if ( 'core' === $target->kind && ( ! $extra || ( ! str_starts_with( $relativePath, 'wp-admin/' ) && ! str_starts_with( $relativePath, 'wp-includes/' ) ) ) ) {
			return false;
		}
		$manifest = $target->manifest;
		if ( null === $manifest || 'sha256' !== $manifest->algorithm || $manifest->fetchedAt->getTimestamp() < time() - 86400 || null === $observedSha256 ) {
			return true;
		}
		return ! in_array( $observedSha256, $manifest->files[ $relativePath ] ?? array(), true );
	}
}
