<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Fixes;

/** Decides one approved setting change. It does not write the setting. */
final class ApprovedSetting {
	public static function pingStatus( string $current ): string {
		return 'open' === $current ? 'closed' : '';
	}

	public static function fileEditorOption( bool $constantDefined ): string {
		return $constantDefined ? '' : '1';
	}

	public static function debugHide( string $current ): string {
		return '1' === $current ? '' : '1';
	}

	public static function debugRestore( string $current ): string {
		return '1' === $current ? '0' : '';
	}

	public static function fileEditorRestore( string $current ): string {
		return '1' === $current ? '0' : '';
	}

	public static function gateOn( string $current ): string {
		return '1' === $current ? '' : '1';
	}

	public static function gateOff( string $current ): string {
		return '1' === $current ? '0' : '';
	}
}
