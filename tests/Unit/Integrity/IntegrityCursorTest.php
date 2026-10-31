<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Integrity;

use AmazingPlugins\Security\Integrity\IntegrityCursor;
use PHPUnit\Framework\TestCase;

final class IntegrityCursorTest extends TestCase {
	public function test_rejects_wrong_version_and_impossible_counters(): void {
		$data            = ( new IntegrityCursor( 'scan-1' ) )->toArray();
		$data['version'] = 2;
		self::assertNull( IntegrityCursor::fromArray( $data ) );
		$data['version']   = 1;
		$data['matched']   = 2;
		$data['processed'] = 1;
		self::assertNull( IntegrityCursor::fromArray( $data ) );
		$data['matched']  = 0;
		$data['packages'] = array(
			'core:6.6:en_US' => array(
				'total'        => -1,
				'checked'      => 0,
				'matched'      => 0,
				'warn'         => 0,
				'inconclusive' => 0,
				'source_url'   => 'https://api.wordpress.org/',
				'fetched_at'   => '2026-09-28T00:00:00+00:00',
			),
		);
		self::assertNull( IntegrityCursor::fromArray( $data ) );
	}
}
