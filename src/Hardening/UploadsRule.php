<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Hardening;

defined( 'ABSPATH' ) || exit;

/** Apache uploads rule text. Writing the file is a separate, confirmed step. */
final class UploadsRule {
	public const BEGIN = '# Begin Amazing Security uploads';

	public const END = '# End Amazing Security uploads';

	public static function snippet(): string {
		return self::BEGIN . "\n<FilesMatch \"\\.(?:php|phtml|php[0-9])$\">\nRequire all denied\n</FilesMatch>\n" . self::END . "\n";
	}

	public static function present( string $existing ): bool {
		return str_contains( $existing, self::BEGIN ) || '' !== \AmazingPlugins\Security\Checks\UploadsExecutionCheck::classify( $existing );
	}

	public static function merge( string $existing ): string {
		if ( self::present( $existing ) ) {
			return $existing;
		}
		$existing = rtrim( $existing );
		if ( '' === $existing ) {
			return self::snippet();
		}
		return $existing . "\n\n" . self::snippet();
	}
}
