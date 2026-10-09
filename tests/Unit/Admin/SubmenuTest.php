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
			array( 'amazing-security', 'amsec-recommendations', 'amsec-accounts', 'amsec-traffic-guard', 'amsec-files', 'amsec-records', 'amsec-settings', 'amsec-assistant' ),
			array_merge( array( Submenu::PARENT ), Submenu::visible() )
		);
	}

	public function test_extra_screens_are_hidden_and_the_scan_page_stays(): void {
		$registered = array(
			'amazing-security',
			'amsec-accounts',
			'amsec-passkeys',
			'amsec-traffic-guard',
			'amsec-tools',
			'amsec-fix-review',
			'amsec-activity',
			'amsec-repair',
			'amsec-guide',
			'amsec-review',
		);
		self::assertSame(
			array( 'amsec-passkeys', 'amsec-tools', 'amsec-fix-review', 'amsec-activity', 'amsec-repair', 'amsec-guide', 'amsec-review' ),
			Submenu::hidden( $registered )
		);
	}
}
