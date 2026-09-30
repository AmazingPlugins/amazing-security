<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Digest;

use AmazingPlugins\Security\Integrity\WordPressOptions;
use AmazingPlugins\Security\Activity\ActivityRepository;

final class DigestHooks {
	public function delivery(): DigestDelivery {
		return new DigestDelivery( new WordPressOptions(), static fn( string $to, string $subject, string $body ): bool => wp_mail( $to, $subject, $body ), (string) get_option( 'admin_email', '' ), admin_url( 'admin.php?page=amazing-security' ) );
	}
	public function ensure(): void {
		if ( '1' !== get_option( 'amsec_digest_enabled' ) ) {
			$this->clear();
			return;
		}
		// Initializing the due date sends nothing; subsequent ticks run through WP-Cron.
		if ( null === get_option( 'amsec_digest_state', null ) ) {
			$this->delivery()->tick( array(), array(), time() );
		}
		if ( ! wp_next_scheduled( 'amsec_weekly_digest_tick' ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'hourly', 'amsec_weekly_digest_tick' );
		}
	}
	public function clear(): void {
		wp_clear_scheduled_hook( 'amsec_weekly_digest_tick' );
	}
	public function tick(): void {
		if ( '1' !== get_option( 'amsec_digest_enabled' ) ) {
			return;
		}
		$this->delivery()->tick( ( new ReportCollector() )->collect(), ( new ActivityRepository( $GLOBALS['wpdb'] ) )->digestCounts( time() ), time() );
	}
}
