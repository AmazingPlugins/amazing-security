<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Vulnerabilities;

use AmazingPlugins\Security\Vulnerabilities\DirectFeedResponse;
use PHPUnit\Framework\TestCase;

final class DirectFeedResponseTest extends TestCase {
	public function test_parses_real_component_response_without_treating_old_source_update_as_failed_fetch(): void {
		$json = file_get_contents( dirname( __DIR__, 2 ) . '/Fixtures/WPVulnerability/plugin-akismet.json' );
		$data = DirectFeedResponse::parse( 'plugin', 'akismet', $json, 1790676000 );
		self::assertNotNull( $data );
		self::assertSame( 'akismet', $data->slug );
		self::assertSame( 1790676000, $data->fetchedAt );
		self::assertCount( 1, $data->records );
		self::assertSame( '3.1.5', $data->records[0]['operator']['max_version'] );
	}

	public function test_null_vulnerability_means_successful_empty_component_response(): void {
		$json = file_get_contents( dirname( __DIR__, 2 ) . '/Fixtures/WPVulnerability/theme-twentytwentyfour.json' );
		$data = DirectFeedResponse::parse( 'theme', 'twentytwentyfour', $json, 1790676000 );
		self::assertNotNull( $data );
		self::assertSame( array(), $data->records );
	}

	public function test_rejects_wrong_component_and_invalid_envelope(): void {
		$json = file_get_contents( dirname( __DIR__, 2 ) . '/Fixtures/WPVulnerability/plugin-akismet.json' );
		self::assertNull( DirectFeedResponse::parse( 'plugin', 'woocommerce', $json, 1790676000 ) );
		self::assertNull( DirectFeedResponse::parse( 'plugin', 'akismet', '{"error":1,"data":null,"updated":1}', 1790676000 ) );
		self::assertNull( DirectFeedResponse::parse( 'plugin', 'akismet', '{"error":0,"data":[],"updated":1}', 1790676000 ) );
	}
}
