<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Sessions;

use AmazingPlugins\Security\Sessions\ApplicationPasswordList;
use PHPUnit\Framework\TestCase;

final class ApplicationPasswordListTest extends TestCase {
	public function test_rows_keep_the_name_and_leave_out_the_secret(): void {
		$uuid = '123e4567-e89b-12d3-a456-426614174000';
		$rows = ApplicationPasswordList::rows(
			array(
				array(
					'uuid'     => $uuid,
					'name'     => 'Phone',
					'created'  => 100,
					'password' => 'secret-hash',
				),
				array(
					'uuid' => 'not-a-uuid',
					'name' => 'Bad',
				),
			)
		);
		self::assertSame(
			array(
				array(
					'uuid'    => $uuid,
					'name'    => 'Phone',
					'created' => 100,
				),
			),
			$rows
		);
		self::assertStringNotContainsString( 'secret-hash', (string) json_encode( $rows ) );
		self::assertSame( $uuid, ApplicationPasswordList::selected( $rows, $uuid ) );
		self::assertSame( '', ApplicationPasswordList::selected( $rows, '123e4567-e89b-12d3-a456-426614174001' ) );
	}
}
