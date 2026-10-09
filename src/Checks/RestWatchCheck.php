<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Checks;

use AmazingPlugins\Security\Findings\CheckResult;
use AmazingPlugins\Security\Findings\State;
use AmazingPlugins\Security\Firewall\BundledRequestRules;
use AmazingPlugins\Security\Scan\ScanContext;
use AmazingPlugins\Security\Scan\SecurityCheck;
use Closure;
use DateTimeImmutable;
use DateTimeZone;

/** Reports whether the observe-only REST request watch is active. It does not enable block mode. */
final class RestWatchCheck implements SecurityCheck {
	private const SOURCE = 'https://developer.wordpress.org/rest-api/';
	private readonly Closure $disabled;

	public function __construct( ?callable $disabled = null ) {
		$this->disabled = Closure::fromCallable(
			$disabled ?? static fn (): bool => defined( 'AMSEC_DISABLE_FIREWALL' ) && AMSEC_DISABLE_FIREWALL
		);
	}

	public function id(): string {
		return 'rest-request-watch';
	}

	public function run( ScanContext $context ): array {
		unset( $context );
		$off   = (bool) ( $this->disabled )();
		$pack  = new BundledRequestRules();
		$count = count( $pack->ids() );
		$ver   = $pack->version();
		return array(
			new CheckResult(
				$this->id(),
				$off ? State::WARN : State::PASS,
				$off
					? 'The REST request watch is disabled by AMSEC_DISABLE_FIREWALL. Public REST queries are not observed. Pack ' . $ver . ' has ' . $count . ' observe rules unused while disabled.'
					: 'The REST request watch is on (observe only). Pack ' . $ver . ' records matches for ' . $count . ' public REST rules and does not block requests.',
				self::SOURCE,
				new DateTimeImmutable( 'now', new DateTimeZone( 'UTC' ) ),
				'medium',
				'complete',
				array(
					'status'     => $off ? 'disabled' : 'observe',
					'pack'       => $ver,
					'rule_count' => $count,
				)
			),
		);
	}
}
