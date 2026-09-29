<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Login;

interface PendingEnrollmentStore {
	public function put( int $userId, string $encryptedSeed ): void;
	public function get( int $userId ): ?string;
	public function clear( int $userId ): void;
}
