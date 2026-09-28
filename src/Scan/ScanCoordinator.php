<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Scan;

use AmazingPlugins\Security\Findings\CheckResult;
use AmazingPlugins\Security\Findings\State;
use DateTimeImmutable;
use DateTimeZone;
use InvalidArgumentException;
use Throwable;

final class ScanCoordinator {
	/** @param SecurityCheck[] $checks */
	public function run( array $checks, ScanContext $context ): ScanRun {
		$ids = array();
		foreach ( $checks as $check ) {
			if ( ! $check instanceof SecurityCheck || isset( $ids[ $check->id() ] ) ) {
				throw new InvalidArgumentException( 'Invalid or duplicate security check.' );
			}
			$ids[ $check->id() ] = true;
		}
		$started = new DateTimeImmutable( 'now', new DateTimeZone( 'UTC' ) );
		$results = array();
		$partial = false;
		foreach ( $checks as $check ) {
			if ( microtime( true ) >= $context->deadline || count( $results ) >= $context->entryLimit ) {
				$partial = true;
				if ( count( $results ) < $context->entryLimit ) {
					$results[] = self::unknown( $check->id(), 'Scan budget reached. This check was not completed.' );
				}
				continue;
			}
			try {
				$checkResults = $check->run( $context );
				if ( ! $checkResults || ! is_array( $checkResults ) || count( $results ) + count( $checkResults ) > $context->entryLimit ) {
					throw new \RuntimeException( 'Check returned no result.' );
				}
				foreach ( $checkResults as $result ) {
					if ( ! $result instanceof CheckResult || microtime( true ) >= $context->deadline ) {
						throw new \RuntimeException( 'Scan budget or result contract exceeded.' );
					}
				}
				array_push( $results, ...$checkResults );
			} catch ( Throwable $error ) {
				$partial = true;
				if ( count( $results ) < $context->entryLimit ) {
					$results[] = self::unknown( $check->id(), 'This check could not be completed.' );
				}
			}
		}
		return new ScanRun( $started, new DateTimeImmutable( 'now', new DateTimeZone( 'UTC' ) ), $results, $partial );
	}

	private static function unknown( string $id, string $summary ): CheckResult {
		return new CheckResult( $id, State::UNKNOWN, $summary, 'https://developer.wordpress.org/advanced-administration/security/hardening/', new DateTimeImmutable( 'now', new DateTimeZone( 'UTC' ) ), 'low', 'unavailable', array() );
	}
}
