<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Checks;

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
					'Error details are hidden for requests that load this plugin. wp-config.php was not changed.',
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
					'Visitors may see WordPress error details. You can hide them for requests that load this plugin. This plugin will not edit wp-config.php.',
					self::SOURCE,
					new DateTimeImmutable( 'now', new DateTimeZone( 'UTC' ) ),
					'high',
					'complete',
					array( 'fix' => 'plugin' )
				),
			);
		}
		return $this->result( $displayed, 'WordPress error details are hidden from visitors.', 'Visitors may see WordPress error details. You can hide them for requests that load this plugin. This plugin will not edit wp-config.php.' );
	}
}
