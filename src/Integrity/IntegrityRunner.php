<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Integrity;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Findings\CheckResult;
use AmazingPlugins\Security\Findings\State;
use AmazingPlugins\Security\Scan\ScanContext;
use DateTimeImmutable;

final class IntegrityRunner {
	public function __construct( private readonly FileReader $reader ) {}

	/** @param IntegrityTarget[] $targets */
	public function step( array $targets, IntegrityCursor $cursor, ScanContext $context ): IntegrityStep {
		$started = microtime( true );
		if ( $cursor->processed >= 5000 || $cursor->bytes >= 134217728 || $cursor->elapsed >= 30.0 ) {
			$cursor->partial = true;
			return new IntegrityStep( $cursor, true );
		}
		$budget    = new IntegrityBudget( min( 250, $context->entryLimit ), min( 33554432, max( 0, 134217728 - $cursor->bytes ) ), min( 5.0, max( 0.0, 30.0 - $cursor->elapsed ), max( 0.0, $context->deadline - $started ) ) );
		$stepCount = 0;
		foreach ( $targets as $target ) {
			$packageKey = $target->manifest->type . ':' . $target->manifest->identity;
			if ( ! isset( $cursor->packages[ $packageKey ] ) ) {
				$cursor->packages[ $packageKey ] = array(
					'total'        => count( $target->manifest->files ),
					'checked'      => 0,
					'matched'      => 0,
					'warn'         => 0,
					'inconclusive' => 0,
					'source_url'   => $target->manifest->sourceUrl,
					'fetched_at'   => $target->manifest->fetchedAt->format( 'c' ),
				);
			}
		}
		foreach ( $targets as $targetIndex => $target ) {
			$packageKey = $target->manifest->type . ':' . $target->manifest->identity;
			if ( $targetIndex < $cursor->targetIndex ) {
				continue;
			}
			$paths = array_keys( $target->manifest->files );
			foreach ( $paths as $fileIndex => $path ) {
				if ( $targetIndex === $cursor->targetIndex && $fileIndex < $cursor->fileIndex ) {
					continue;
				}
				if ( $cursor->processed >= 5000 || $cursor->bytes + $budget->bytes() >= 134217728 || $cursor->elapsed + microtime( true ) - $started >= 30.0 ) {
					$cursor->partial  = true;
					$cursor->bytes   += $budget->bytes();
					$cursor->elapsed += microtime( true ) - $started;
					return new IntegrityStep( $cursor, true );
				}
				if ( $stepCount >= min( 250, $context->entryLimit ) || ! $budget->hasTime() ) {
					$cursor->bytes   += $budget->bytes();
					$cursor->elapsed += microtime( true ) - $started;
					return new IntegrityStep( $cursor, false );
				}
				$result = $this->reader->hash( $target->root, $path, $target->manifest->algorithm, $budget );
				if ( 'budget' === $result->state ) {
					$cursor->partial  = true;
					$cursor->bytes   += $budget->bytes();
					$cursor->elapsed += microtime( true ) - $started;
					return new IntegrityStep( $cursor, true );
				}
				++$stepCount;
				++$cursor->processed;
				++$cursor->packages[ $packageKey ]['checked'];
				$cursor->targetIndex = $targetIndex;
				$cursor->fileIndex   = $fileIndex + 1;
				if ( 'ok' === $result->state && in_array( $result->digest, $target->manifest->files[ $path ], true ) ) {
					++$cursor->matched;
					++$cursor->packages[ $packageKey ]['matched'];
					continue;
				}
				$state = 'ok' === $result->state || ( 'missing' === $result->state && 'core' === $target->manifest->type && str_ends_with( $path, '.php' ) ) ? State::WARN : State::INCONCLUSIVE;
				++$cursor->packages[ $packageKey ][ State::WARN === $state ? 'warn' : 'inconclusive' ];
				if ( count( $cursor->findings ) >= 250 ) {
					$cursor->partial = true;
					continue;
				}
				$cursor->findings[] = new CheckResult(
					'integrity-file',
					$state,
					'ok' === $result->state ? 'Release file differs from the published checksum.' : ( 'missing' === $result->state ? 'Release file is missing.' : 'Release file could not be checked.' ),
					$target->manifest->sourceUrl,
					new DateTimeImmutable(),
					'high',
					State::INCONCLUSIVE === $state ? 'partial' : 'complete',
					array(
						'package_type'        => $target->manifest->type,
						'package'             => $target->manifest->identity,
						'path'                => $path,
						'reason'              => $result->state,
						'observed_sha256'     => $result->sha256,
						'algorithm'           => $target->manifest->algorithm,
						'manifest_fetched_at' => $target->manifest->fetchedAt->format( 'c' ),
					),
					substr( hash( 'sha256', $target->manifest->type . ':' . $target->manifest->identity . ':' . $path ), 0, 32 )
				);
			}
			$cursor->targetIndex = $targetIndex + 1;
			$cursor->fileIndex   = 0;
		}
		$cursor->bytes   += $budget->bytes();
		$cursor->elapsed += microtime( true ) - $started;
		return new IntegrityStep( $cursor, true );
	}
}
