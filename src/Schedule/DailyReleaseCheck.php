<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Schedule;

/** Whether the daily cycle may compare release files with WordPress.org. Off until an administrator turns it on. */
final class DailyReleaseCheck {
	public const OPTION = 'amsec_daily_release_check';

	public static function enabled(): bool {
		return '1' === get_option( self::OPTION, '0' );
	}

	/** The daily cycle starts at the release comparison only when it is on. Otherwise it goes straight to the local file scan. */
	public static function firstStage( bool $enabled ): string {
		return $enabled ? 'integrity' : 'files';
	}

	public static function firstHook( bool $enabled ): string {
		return $enabled ? 'amsec_integrity_tick' : 'amsec_file_tick';
	}
}
