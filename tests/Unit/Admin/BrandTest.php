<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Admin;

require_once dirname( __DIR__, 3 ) . '/src/Admin/Brand.php';

use AmazingPlugins\Security\Admin\Brand;
use PHPUnit\Framework\TestCase;

/** Public links. This test does not bootstrap WordPress. */
final class BrandTest extends TestCase {
	public function test_the_docs_and_guide_links_point_at_the_public_site(): void {
		self::assertSame( 'https://amazingplugins.com/plugins/ironlatch-security-scanner/', Brand::DOCS );
		self::assertSame( 'https://amazingplugins.com/wordpress-security/', Brand::GUIDE );
	}

	public function test_the_menu_icon_is_one_colour_svg_so_wordpress_can_recolour_it(): void {
		self::assertStringStartsWith( 'data:image/svg+xml;base64,', Brand::MENU_ICON );
		$svg = base64_decode( substr( Brand::MENU_ICON, strlen( 'data:image/svg+xml;base64,' ) ), true );
		self::assertIsString( $svg );
		self::assertStringContainsString( 'viewBox="0 0 20 20"', $svg );
		self::assertNotNull( simplexml_load_string( $svg ) );
		preg_match_all( '/(?:fill|stroke)="(#[0-9a-fA-F]{3,6})"/', $svg, $colours );
		self::assertCount( 1, array_unique( $colours[1] ) );
		self::assertStringNotContainsString( '<script', $svg );
	}
}
