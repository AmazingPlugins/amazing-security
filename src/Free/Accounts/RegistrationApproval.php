<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Free\Accounts;

defined( 'ABSPATH' ) || exit;

/** New accounts can wait for approval. Missing meta is not pending. */
final class RegistrationApproval {
	public const OPTION = 'amsec_approve_registrations';
	public const META   = 'amsec_registration_pending';

	public static function enabled( mixed $option ): bool {
		return '1' === (string) $option;
	}

	public static function flagged( mixed $meta ): bool {
		return 1 === $meta || '1' === $meta;
	}

	public static function blocks( bool $enabled, mixed $meta ): bool {
		return $enabled && self::flagged( $meta );
	}
}
