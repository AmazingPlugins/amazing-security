<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\FileScan;

use AmazingPlugins\Security\FileScan\FileScanCursor;
use PHPUnit\Framework\TestCase;

final class FileScanCursorTest extends TestCase {
	public function test_rejects_absolute_or_malformed_resume_paths(): void {
		$cursor        = new FileScanCursor( 'scan-1' );
		$data          = $cursor->toArray();
		$data['stack'] = array(
			array(
				'path' => '/etc',
				'last' => '',
				'hash' => str_repeat( 'a', 64 ),
			),
		);
		self::assertNull( FileScanCursor::fromArray( $data ) );
		$data['stack'][0]['path'] = '../etc';
		self::assertNull( FileScanCursor::fromArray( $data ) );
		$data['stack'][0]['path'] = 'safe';
		self::assertNotNull( FileScanCursor::fromArray( $data ) );
	}

	public function test_serialized_cursor_does_not_store_root_or_contents(): void {
		$cursor     = new FileScanCursor( 'scan-1' );
		$serialized = json_encode( $cursor->toArray() );
		self::assertStringNotContainsString( '/var/www', $serialized );
		self::assertStringNotContainsString( 'source_code', $serialized );
	}
}
