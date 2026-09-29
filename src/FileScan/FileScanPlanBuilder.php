<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\FileScan;

use AmazingPlugins\Security\Integrity\DiscoveryResult;

final class FileScanPlanBuilder {
	/** @return FileScanTarget[] */
	public function build( DiscoveryResult $discovery, array $plugins, array $themes, string $uploadsRoot ): array {
		$targets     = array( new FileScanTarget( 'uploads', 'uploads', $uploadsRoot ) );
		$coreTargets = array();
		$accepted    = array();
		foreach ( $discovery->targets as $target ) {
			$key              = $target->manifest->type . ':' . $target->manifest->identity;
			$accepted[ $key ] = $target->manifest;
			if ( 'core' === $target->manifest->type ) {
				$coreTargets[] = new FileScanTarget( $target->manifest->identity, 'core', $target->root, $target->manifest );
			}
		}
		foreach ( array(
			'plugin' => $plugins,
			'theme'  => $themes,
		) as $kind => $rows ) {
			foreach ( $rows as $row ) {
				$singleFile = is_string( $row['single_file'] ?? null ) ? $row['single_file'] : null;
				if ( ! isset( $row['slug'], $row['version'], $row['root'] ) || ( 'unsupported_local_path' === ( $row['update_uri'] ?? '' ) && null === $singleFile ) ) {
					continue;
				}
				$identity  = $row['slug'] . ':' . $row['version'];
				$targets[] = new FileScanTarget( $identity, $kind, $row['root'], $accepted[ $kind . ':' . $identity ] ?? null, $singleFile );
			}
		}
		return array_merge( $targets, $coreTargets );
	}
}
