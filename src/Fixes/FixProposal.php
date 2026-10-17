<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Fixes;

defined( 'ABSPATH' ) || exit;

use InvalidArgumentException;

final class FixProposal {
	public readonly string $fingerprint;

	public function __construct(
		public readonly string $id,
		public readonly string $findingId,
		public readonly string $recipeId,
		public readonly string $beforeMode,
		public readonly string $afterMode,
		public readonly int $requesterId,
		public readonly int $createdAt,
		public readonly int $expiresAt,
		public readonly string $status = 'pending',
		public readonly ?int $approverId = null,
		public readonly ?int $appliedAt = null,
		public readonly ?int $rolledBackAt = null
	) {
		if ( ! preg_match( '/^[a-f0-9]{32}$/D', $id ) || ! preg_match( '/^[a-f0-9]{32}$/D', $findingId ) || null === ( new RecipeCatalog() )->transition( $recipeId, $beforeMode ) || ( new RecipeCatalog() )->transition( $recipeId, $beforeMode )['after'] !== $afterMode || $requesterId < 1 || $createdAt < 1 || $expiresAt <= $createdAt || $expiresAt > $createdAt + 900 || ! in_array( $status, array( 'pending', 'applied', 'refused', 'expired', 'rolled_back' ), true ) ) {
			throw new InvalidArgumentException( 'Invalid fix proposal.' );
		}
		$this->fingerprint = hash( 'sha256', 'amsec_login_rate_mode:' . $beforeMode );
	}

	public function isExpired( int $now ): bool {
		return $now >= $this->expiresAt;
	}

	public function canRollback( int $now ): bool {
		return 'applied' === $this->status && null !== $this->appliedAt && $now < $this->appliedAt + 86400;
	}
}
