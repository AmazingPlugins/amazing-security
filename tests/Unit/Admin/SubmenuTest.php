<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Admin;

require_once dirname( __DIR__, 3 ) . '/src/Admin/Submenu.php';

use AmazingPlugins\Security\Admin\Submenu;
use PHPUnit\Framework\TestCase;

/** Side-menu size. This test does not bootstrap WordPress. */
final class SubmenuTest extends TestCase {
	public function test_the_side_menu_is_scan_recommendations_authentication_traffic_files_records_and_settings(): void {
		self::assertSame(
			array( 'ironlatch-security-scanner', 'ironlatch-recommendations', 'ironlatch-accounts', 'ironlatch-traffic-guard', 'ironlatch-files', 'ironlatch-records', 'ironlatch-settings', 'ironlatch-assistant' ),
			array_merge( array( Submenu::PARENT ), Submenu::visible() )
		);
	}

	public function test_extra_screens_are_hidden_and_the_scan_page_stays(): void {
		$registered = array(
			'ironlatch-security-scanner',
			'ironlatch-accounts',
			'ironlatch-traffic-guard',
			'ironlatch-tools',
			'ironlatch-fix-review',
			'ironlatch-activity',
			'ironlatch-repair',
			'ironlatch-guide',
			'ironlatch-review',
		);
		self::assertSame(
			array( 'ironlatch-tools', 'ironlatch-fix-review', 'ironlatch-activity', 'ironlatch-repair', 'ironlatch-guide', 'ironlatch-review' ),
			Submenu::hidden( $registered )
		);
	}
}
