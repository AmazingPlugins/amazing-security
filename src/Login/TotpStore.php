<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Login;

defined( 'ABSPATH' ) || exit;

interface TotpStore {
	public function enroll( int $userId, string $encryptedSecret, array $recoveryHashes ): bool;
	public function isEnrolled( int $userId ): bool;
	public function encryptedSecret( int $userId ): ?string;
	public function lastStep( int $userId ): ?int;
	public function consumeStep( int $userId, int $step ): bool;
	public function consumeRecoveryCode( int $userId, string $code ): bool;
	public function hasRecoveryCode( int $userId, string $code ): bool;
	public function replaceRecoveryCodes( int $userId, array $hashes ): bool;
	public function disable( int $userId ): bool;
}
