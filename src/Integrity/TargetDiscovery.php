<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Integrity;

use AmazingPlugins\Security\Findings\CheckResult;
use AmazingPlugins\Security\Findings\State;
use DateTimeImmutable;

final class TargetDiscovery {
	public function __construct( private readonly ChecksumManifestProvider $provider ) {}

	/** @param array<int,array{slug:string,version:string,root:string,update_uri:string}> $plugins */
	public function discover( string $coreVersion, string $coreLocale, string $coreRoot, array $plugins ): DiscoveryResult {
		$targets  = array();
		$findings = array();
		$partial  = false;
		$started  = microtime( true );
		$core     = $this->provider->core( $coreVersion, $coreLocale );
		if ( null !== $core->manifest ) {
			$targets[] = new IntegrityTarget( $core->manifest, $coreRoot );
		} else {
			$findings[] = $this->unknown( 'core:' . $coreVersion . ':' . $coreLocale, $core->reason );
			$partial    = true;
		}
		$seen = 0;
		foreach ( $plugins as $plugin ) {
			$identity = 'plugin:' . $plugin['slug'] . ':' . $plugin['version'];
			if ( '' !== $plugin['update_uri'] ) {
				$findings[] = $this->unknown( $identity, 'unsupported_local_path' === $plugin['update_uri'] ? 'unsupported_local_path' : 'non_wordpress_org_origin' );
				$partial    = true;
				continue;
			}
			if ( $seen >= 10 || microtime( true ) - $started >= 10 ) {
				$findings[] = $this->unknown( $identity, 'package_limit' );
				$partial    = true;
				continue;
			}
			++$seen;
			$result = $this->provider->plugin( $plugin['slug'], $plugin['version'] );
			if ( null === $result->manifest ) {
				$findings[] = $this->unknown( $identity, $result->reason );
				$partial    = true;
				continue;
			}
			$targets[] = new IntegrityTarget( $result->manifest, $plugin['root'] );
		}
		$identities = array_map(
			static function ( IntegrityTarget $target ): string {
				$files = $target->manifest->files;
				ksort( $files );
				// phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- This pure fingerprint also runs in tests without WordPress loaded.
				return $target->manifest->type . ':' . $target->manifest->identity . ':' . hash( 'sha256', json_encode( $files, JSON_THROW_ON_ERROR ) );
			},
			$targets
		);
		return new DiscoveryResult( $targets, $findings, hash( 'sha256', implode( '|', $identities ) ), $partial );
	}

	private function unknown( string $package, string $reason ): CheckResult {
		return new CheckResult(
			'integrity-package',
			State::UNKNOWN,
			'Package could not be verified against a WordPress.org release.',
			'https://wordpress.org/plugins/',
			new DateTimeImmutable(),
			'low',
			'unavailable',
			array(
				'package' => $package,
				'reason'  => $reason,
			),
			substr( hash( 'sha256', $package ), 0, 32 )
		);
	}
}
