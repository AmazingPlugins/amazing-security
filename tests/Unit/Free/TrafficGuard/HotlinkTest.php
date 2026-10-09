<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Free\TrafficGuard;

use AmazingPlugins\Security\Free\TrafficGuard\Hotlink;
use PHPUnit\Framework\TestCase;

final class HotlinkTest extends TestCase {
	public function test_hotlink_allows_empty_and_same_host_and_blocks_a_different_host(): void {
		$hotlink = new Hotlink();
		$server  = array(
			'REQUEST_URI'  => '/wp-content/uploads/2024/10/cat.jpg?size=large',
			'HTTP_REFERER' => '',
		);
		self::assertFalse( $hotlink->blocked( true, $server, 'site.example' ) );

		$server['HTTP_REFERER'] = 'https://site.example/gallery';
		self::assertFalse( $hotlink->blocked( true, $server, 'site.example' ) );

		$server['HTTP_REFERER'] = 'https://Site.Example/gallery';
		self::assertFalse( $hotlink->blocked( true, $server, 'site.example' ) );

		$server['HTTP_REFERER'] = 'http://other.example/page';
		self::assertTrue( $hotlink->blocked( true, $server, 'site.example' ) );
		self::assertFalse( $hotlink->blocked( false, $server, 'site.example' ) );

		$server['REQUEST_URI'] = '/wp-content/themes/photo.jpg';
		self::assertFalse( $hotlink->blocked( true, $server, 'site.example' ) );
	}
}
