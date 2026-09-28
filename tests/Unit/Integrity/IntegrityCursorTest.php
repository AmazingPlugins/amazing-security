<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Integrity;

use AmazingPlugins\Security\Integrity\IntegrityCursor;
use PHPUnit\Framework\TestCase;

final class IntegrityCursorTest extends TestCase {
	public function test_rejects_wrong_version_and_impossible_counters(): void {
		$data = ( new IntegrityCursor( 'scan-1' ) )->toArray();
		$data['version'] = 2;
		self::assertNull( IntegrityCursor::fromArray( $data ) );
		$data['version'] = 1;
		$data['matched'] = 2;
		$data['processed'] = 1;
		self::assertNull( IntegrityCursor::fromArray( $data ) );
	}
}
