<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Mcp;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Fixes\FixRepository;
use Throwable;

final class FixGateway {
	public function __construct( private readonly FixRepository $repository ) {}

	public function status( string $id, int $now ): array {
		if ( ! preg_match( '/^[a-f0-9]{32}$/D', $id ) ) {
			return array(
				'schema_version' => 1,
				'state'          => 'invalid_input',
			);
		}
		try {
			$proposal = $this->repository->get( $id );
			if ( null === $proposal ) {
				return array(
					'schema_version' => 1,
					'state'          => 'missing',
				);
			}
			$state = 'pending' === $proposal->status && $proposal->isExpired( $now ) ? 'expired' : $proposal->status;
			return array(
				'schema_version' => 1,
				'state'          => $state,
				'proposal_id'    => $proposal->id,
				'recipe_id'      => $proposal->recipeId,
				'before'         => $proposal->beforeMode,
				'after'          => $proposal->afterMode,
				'expires_at'     => gmdate( 'c', $proposal->expiresAt ),
				'applied_at'     => null === $proposal->appliedAt ? null : gmdate( 'c', $proposal->appliedAt ),
				'rolled_back_at' => null === $proposal->rolledBackAt ? null : gmdate( 'c', $proposal->rolledBackAt ),
			);
		} catch ( Throwable ) {
			return array(
				'schema_version' => 1,
				'state'          => 'unavailable',
			);
		}
	}
}
