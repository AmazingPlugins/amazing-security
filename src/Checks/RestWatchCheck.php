<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Checks;

defined( 'ABSPATH' ) || exit;

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
					? sprintf(
						/* translators: 1: version of the bundled REST rule pack, 2: number of observe rules. */
						__( 'The REST request watch is disabled by AMSEC_DISABLE_FIREWALL. Public REST queries are not observed. Pack %1$s has %2$s observe rules unused while disabled.', 'amsec-security-scanner' ),
						$ver,
						$count
					)
					: sprintf(
						/* translators: 1: version of the bundled REST rule pack, 2: number of public REST rules. */
						__( 'The REST request watch is on (observe only). Pack %1$s records matches for %2$s public REST rules and does not block requests.', 'amsec-security-scanner' ),
						$ver,
						$count
					),
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
