<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Firewall;

use AmazingPlugins\Security\Firewall\RequestInspector;
use PHPUnit\Framework\TestCase;

final class RequestInspectorTest extends TestCase {
	public function test_detects_specific_query_patterns_without_returning_content(): void {
		$inspector = new RequestInspector();
		self::assertSame( array( 'AS-REST-001' ), $inspector->inspect( array( 'file' => '../private/config.php' ), false )['rules'] );
		self::assertSame( array( 'AS-REST-002' ), $inspector->inspect( array( 'q' => '1 UNION ALL SELECT 2' ), false )['rules'] );
		self::assertSame( array(), $inspector->inspect( array( 'q' => 'A normal search' ), false )['rules'] );
	}

	public function test_skips_credentials_and_authenticated_requests(): void {
		$inspector = new RequestInspector();
		self::assertSame( 'skip', $inspector->inspect( array( 'q' => '../private' ), true )['state'] );
		self::assertSame( 'pass', $inspector->inspect( array( 'password' => '../private', 'q' => 'normal' ), false )['state'] );
	}

	public function test_nested_or_oversized_query_is_partial_not_clean(): void {
		$inspector = new RequestInspector();
		self::assertSame( 'partial', $inspector->inspect( array( 'q' => array( 'x' => '../private' ) ), false )['state'] );
		self::assertSame( 'partial', $inspector->inspect( array( 'q' => str_repeat( 'a', 9000 ) ), false )['state'] );
	}
}
