<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Findings;

defined( 'ABSPATH' ) || exit;

final class State {
	public const PASS         = 'pass';
	public const WARN         = 'warn';
	public const CRITICAL     = 'critical';
	public const FAIL         = 'fail';
	public const UNKNOWN      = 'unknown';
	public const INCONCLUSIVE = 'inconclusive';

	public static function isValid( string $state ): bool {
		return in_array( $state, array( self::PASS, self::WARN, self::CRITICAL, self::FAIL, self::UNKNOWN, self::INCONCLUSIVE ), true );
	}
}
