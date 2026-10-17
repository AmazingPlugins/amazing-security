<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Fixes;

defined( 'ABSPATH' ) || exit;

interface FixRepository {
	public function create( FixProposal $proposal ): bool;
	public function get( string $id ): ?FixProposal;
	public function apply( string $id, int $approverId, int $now ): string;
	public function rollback( string $id, int $approverId, int $now ): string;
	public function audit( string $id ): array;
	public function recentForUser( int $userId, int $since ): int;
	public function pendingCount( int $now ): int;
}
