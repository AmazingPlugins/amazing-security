<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Admin;

require_once dirname( __DIR__, 3 ) . '/src/Admin/Brand.php';

use AmazingPlugins\Security\Admin\Brand;
use PHPUnit\Framework\TestCase;

/** Public links. This test does not bootstrap WordPress. */
final class BrandTest extends TestCase {
	public function test_the_docs_and_guide_links_point_at_the_public_site(): void {
		self::assertSame( 'https://amazingplugins.com/plugins/amsec-security-scanner/', Brand::DOCS );
		self::assertSame( 'https://amazingplugins.com/wordpress-security/', Brand::GUIDE );
	}
}
