<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Bots;

defined( 'ABSPATH' ) || exit;

final class BotPolicy {
	public static function trapSuspicious( mixed $value ): bool {
		return null !== $value && ( ! is_string( $value ) || strlen( $value ) > 128 || '' !== trim( $value ) );
	}

	public static function reject( string $mode, bool $trap, ?int $count, int $limit ): bool {
		return 'block' === $mode && ( $trap || ( null !== $count && $count > $limit ) );
	}
}
