<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Checks;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Findings\CheckResult;
use AmazingPlugins\Security\Findings\State;
use AmazingPlugins\Security\Scan\ScanContext;
use AmazingPlugins\Security\Scan\SecurityCheck;
use DateTimeImmutable;
use DateTimeZone;

/** Summarizes the existing file-mode check. It does not change modes. */
final class FileModesCheck implements SecurityCheck {
	private const SOURCE = 'https://developer.wordpress.org/advanced-administration/security/hardening/';

	public function __construct( private readonly array $paths ) {}

	public function id(): string {
		return 'file-modes';
	}

	public function run( ScanContext $context ): array {
		$rows    = ( new FilesystemPermissionsCheck( $this->paths ) )->run( $context );
		$warn    = 0;
		$unknown = 0;
		foreach ( $rows as $row ) {
			if ( State::WARN === $row->state ) {
				++$warn;
			} elseif ( State::UNKNOWN === $row->state ) {
				++$unknown;
			}
		}
		$state   = $warn > 0 ? State::WARN : ( $unknown > 0 || array() === $rows ? State::UNKNOWN : State::PASS );
		$summary = match ( $state ) {
			State::WARN => __( 'A listed location is world-writable, or the configuration file is world-readable. Ask the host before changing modes.', 'amazingplugins-security-scanner' ),
			State::UNKNOWN => __( 'A listed location could not be read. Ask the host to review it.', 'amazingplugins-security-scanner' ),
			default => __( 'No selected world-write or configuration world-read mode was found.', 'amazingplugins-security-scanner' ),
		};
		return array(
			new CheckResult(
				$this->id(),
				$state,
				$summary . ' This check does not change file modes.',
				self::SOURCE,
				new DateTimeImmutable( 'now', new DateTimeZone( 'UTC' ) ),
				State::UNKNOWN === $state ? 'low' : 'medium',
				State::UNKNOWN === $state ? 'unavailable' : 'partial',
				array(
					'warn_count'    => $warn,
					'unknown_count' => $unknown,
				)
			),
		);
	}
}
