<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\FileScan;

use AmazingPlugins\Security\Integrity\DiscoveryResult;

final class FileScanPlanBuilder {
	/** @return FileScanTarget[] */
	public function build( DiscoveryResult $discovery, array $plugins, array $themes, string $uploadsRoot ): array {
		$targets  = array();
		$accepted = array();
		foreach ( $discovery->targets as $target ) {
			$key              = $target->manifest->type . ':' . $target->manifest->identity;
			$accepted[ $key ] = $target->manifest;
			if ( 'core' === $target->manifest->type ) {
				$targets[] = new FileScanTarget( $target->manifest->identity, 'core', $target->root, $target->manifest );
			}
		}
		foreach ( array(
			'plugin' => $plugins,
			'theme'  => $themes,
		) as $kind => $rows ) {
			foreach ( $rows as $row ) {
				if ( ! isset( $row['slug'], $row['version'], $row['root'] ) || 'unsupported_local_path' === ( $row['update_uri'] ?? '' ) ) {
					continue;
				}
				$identity  = $row['slug'] . ':' . $row['version'];
				$targets[] = new FileScanTarget( $identity, $kind, $row['root'], $accepted[ $kind . ':' . $identity ] ?? null );
			}
		}
		$targets[] = new FileScanTarget( 'uploads', 'uploads', $uploadsRoot );
		return $targets;
	}
}
