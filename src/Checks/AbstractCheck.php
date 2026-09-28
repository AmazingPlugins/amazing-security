<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Checks;

use AmazingPlugins\Security\Findings\CheckResult;
use AmazingPlugins\Security\Findings\State;
use AmazingPlugins\Security\Scan\ScanContext;
use AmazingPlugins\Security\Scan\SecurityCheck;
use DateTimeImmutable;
use DateTimeZone;

abstract class AbstractCheck implements SecurityCheck {
	protected const SOURCE = 'https://developer.wordpress.org/advanced-administration/security/hardening/';

	public function __construct( protected readonly Values $values ) {}

	protected function result( ?bool $condition, string $pass, string $warn ): array {
		$state   = null === $condition ? State::UNKNOWN : ( $condition ? State::WARN : State::PASS );
		$summary = null === $condition ? 'Could not inspect this setting.' : ( $condition ? $warn : $pass );
		return array( new CheckResult( $this->id(), $state, $summary, self::SOURCE, new DateTimeImmutable( 'now', new DateTimeZone( 'UTC' ) ), null === $condition ? 'low' : 'high', null === $condition ? 'unavailable' : 'complete', array() ) );
	}
}
