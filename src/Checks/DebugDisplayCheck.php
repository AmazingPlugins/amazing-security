<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Checks;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Findings\CheckResult;
use AmazingPlugins\Security\Findings\State;
use AmazingPlugins\Security\Scan\ScanContext;
use DateTimeImmutable;
use DateTimeZone;

final class DebugDisplayCheck extends AbstractCheck {
	public function id(): string {
		return 'debug-display';
	}

	public function run( ScanContext $context ): array {
		if ( $this->values->debugHiddenByPlugin() ) {
			return array(
				new CheckResult(
					$this->id(),
					State::PASS,
					__( 'Error details are hidden for requests that load this plugin. wp-config.php was not changed.', 'amazingplugins-security-scanner' ),
					self::SOURCE,
					new DateTimeImmutable( 'now', new DateTimeZone( 'UTC' ) ),
					'high',
					'complete',
					array( 'fix' => 'plugin-on' )
				),
			);
		}
		$displayed = $this->values->debugDisplayed();
		if ( true === $displayed ) {
			return array(
				new CheckResult(
					$this->id(),
					State::WARN,
					__( 'Visitors may see WordPress error details. You can hide them for requests that load this plugin. This plugin will not edit wp-config.php.', 'amazingplugins-security-scanner' ),
					self::SOURCE,
					new DateTimeImmutable( 'now', new DateTimeZone( 'UTC' ) ),
					'high',
					'complete',
					array( 'fix' => 'plugin' )
				),
			);
		}
		return $this->result( $displayed, __( 'WordPress error details are hidden from visitors.', 'amazingplugins-security-scanner' ), __( 'Visitors may see WordPress error details. You can hide them for requests that load this plugin. This plugin will not edit wp-config.php.', 'amazingplugins-security-scanner' ) );
	}
}
