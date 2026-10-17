<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Fixes;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Findings\CheckResult;
use AmazingPlugins\Security\Findings\FindingsRepository;
use AmazingPlugins\Security\Scan\ScanRun;
use Closure;
use Throwable;

final class FixProposalService {
	private readonly Closure $latestRun;
	private readonly Closure $readMode;
	private readonly Closure $reviewUrl;

	public function __construct( private readonly FixRepository $repository, ?callable $latestRun = null, ?callable $readMode = null, ?callable $reviewUrl = null ) {
		$this->latestRun = Closure::fromCallable( $latestRun ?? static fn(): ?ScanRun => ( new FindingsRepository() )->latest() );
		$this->readMode  = Closure::fromCallable( $readMode ?? static fn(): mixed => get_option( 'amsec_login_rate_mode', null ) );
		$this->reviewUrl = Closure::fromCallable( $reviewUrl ?? static fn( string $id ): string => admin_url( 'admin.php?page=amsec-fix-review&proposal=' . $id ) );
	}

	public function propose( string $findingId, string $recipeId, int $requesterId, int $now ): array {
		if ( $requesterId < 1 || ! preg_match( '/^[a-f0-9]{32}$/D', $findingId ) || ! in_array( $recipeId, array( 'login-rate-observe', 'login-rate-block' ), true ) ) {
			return $this->result( 'invalid_input' );
		}
		try {
			$run = ( $this->latestRun )();
			if ( ! $run instanceof ScanRun || $run->finishedAt->getTimestamp() > $now + 300 || $run->finishedAt->getTimestamp() <= $now - 86400 ) {
				return $this->result( 'stale_report' );
			}
			if ( ! hash_equals( substr( hash( 'sha256', 'hardening:login-rate-mode' ), 0, 32 ), $findingId ) ) {
				return $this->result( 'not_applicable' );
			}
			$finding = null;
			foreach ( $run->results as $candidate ) {
				if ( $candidate instanceof CheckResult && 'login-rate-mode' === $candidate->checkId ) {
					$finding = $candidate;
					break;
				}
			}
			if ( null === $finding || 'warn' !== $finding->state || 'complete' !== $finding->coverage || $finding->testedAt->getTimestamp() <= $now - 86400 ) {
				return $this->result( 'not_applicable' );
			}
			$raw  = ( $this->readMode )();
			$mode = null === $raw ? 'off' : $raw;
			if ( ! is_string( $mode ) || ( $finding->evidence['mode'] ?? null ) !== $mode ) {
				return $this->result( 'not_applicable' );
			}
			$transition = ( new RecipeCatalog() )->transition( $recipeId, $mode );
			if ( null === $transition ) {
				return $this->result( 'not_applicable' );
			}
			if ( $this->repository->recentForUser( $requesterId, $now - 3600 ) >= 5 || $this->repository->pendingCount( $now ) >= 20 ) {
				return $this->result( 'quota' );
			}
			$id       = bin2hex( random_bytes( 16 ) );
			$proposal = new FixProposal( $id, $findingId, $recipeId, $transition['before'], $transition['after'], $requesterId, $now, $now + 900 );
			if ( ! $this->repository->create( $proposal ) ) {
				return $this->result( 'unavailable' );
			}
			return array(
				'schema_version' => 1,
				'state'          => 'pending',
				'proposal_id'    => $id,
				'before'         => $proposal->beforeMode,
				'after'          => $proposal->afterMode,
				'expires_at'     => gmdate( 'c', $proposal->expiresAt ),
				'review_url'     => ( $this->reviewUrl )( $id ),
			);
		} catch ( Throwable ) {
			return $this->result( 'unavailable' );
		}
	}

	private function result( string $state ): array {
		return array(
			'schema_version' => 1,
			'state'          => $state,
		);
	}
}
