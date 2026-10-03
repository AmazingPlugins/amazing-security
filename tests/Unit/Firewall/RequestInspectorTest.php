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
		self::assertSame( array( 'AS-REST-003' ), $inspector->inspect( array( 'q' => '%3Cscript%3E' ), false )['rules'] );
		self::assertSame( array( 'AS-REST-004' ), $inspector->inspect( array( 'q' => 'php://filter' ), false )['rules'] );
		self::assertSame( array(), $inspector->inspect( array( 'q' => 'A normal search' ), false )['rules'] );
		self::assertSame( array(), $inspector->inspect( array( 'q' => 'script notes' ), false )['rules'] );
		self::assertSame( array( 'AS-REST-006' ), $inspector->inspect( array( 'q' => 'onerror=alert' ), false )['rules'] );
		self::assertSame( array(), $inspector->inspect( array( 'q' => 'onload handler' ), false )['rules'] );
		self::assertSame( array(), $inspector->inspect( array( 'q' => '&#60;script&#62;' ), false )['rules'] );
		self::assertSame( array( 'AS-REST-005' ), $inspector->inspect( array( 'q' => "%00" ), false )['rules'] );
		self::assertSame( array( 'AS-REST-005' ), $inspector->inspect( array( 'q' => '%2500' ), false )['rules'] );
		self::assertSame( array( 'AS-REST-001' ), $inspector->inspect( array( 'q' => '%252e%252e%252fsecret' ), false )['rules'] );
		self::assertSame( array( 'AS-REST-005' ), $inspector->inspect( array( 'q' => '%252500' ), false )['rules'] );
		self::assertSame( array( 'AS-REST-005' ), $inspector->inspect( array( 'q' => '%25252500' ), false )['rules'] );
		self::assertSame( array( 'AS-REST-005' ), $inspector->inspect( array( 'q' => '%2525252500' ), false )['rules'] );
		self::assertSame( array( 'AS-REST-005' ), $inspector->inspect( array( 'q' => '%252525252500' ), false )['rules'] );
		self::assertSame( array(), $inspector->inspect( array( 'q' => '%25252525252500' ), false )['rules'] );
		self::assertSame( array( 'AS-REST-001' ), $inspector->inspect( array( 'note' => array( 'path' => '../private' ) ), false )['rules'] );
		self::assertSame( array( 'AS-REST-001' ), $inspector->inspect( array( 'note' => array( 'path' => array( 'inner' => '../private' ) ) ), false )['rules'] );
		self::assertSame( array( 'AS-REST-001' ), $inspector->inspect( array( 'note' => array( 'path' => array( 'inner' => array( 'deeper' => '../private' ) ) ) ), false )['rules'] );
		self::assertSame( array( 'AS-REST-001' ), $inspector->inspect( array( 'note' => array( 'path' => array( 'inner' => array( 'deeper' => array( 'last' => '../private' ) ) ) ) ), false )['rules'] );
		self::assertSame( array( 'AS-REST-001' ), $inspector->inspect( array( 'note' => array( 'path' => array( 'inner' => array( 'deeper' => array( 'last' => array( 'stop' => '../private' ) ) ) ) ) ), false )['rules'] );
		self::assertSame( 'observe', $inspector->inspect( array( 'note' => array( 'path' => array( 'inner' => array( 'deeper' => array( 'last' => array( 'stop' => '../private' ) ) ) ) ) ), false )['state'] );
		self::assertSame( array(), $inspector->inspect( array( 'note' => array( 'path' => array( 'inner' => array( 'deeper' => array( 'last' => array( 'stop' => array( 'end' => '../private' ) ) ) ) ) ) ), false )['rules'] );
		self::assertSame( 'partial', $inspector->inspect( array( 'note' => array( 'path' => array( 'inner' => array( 'deeper' => array( 'last' => array( 'stop' => array( 'end' => '../private' ) ) ) ) ) ) ), false )['state'] );
	}

	public function test_skips_credentials_and_authenticated_requests(): void {
		$inspector = new RequestInspector();
		self::assertSame( 'skip', $inspector->inspect( array( 'q' => '../private' ), true )['state'] );
		self::assertSame( 'pass', $inspector->inspect( array( 'password' => '../private', 'q' => 'normal' ), false )['state'] );
	}

	public function test_nested_or_oversized_query_is_partial_not_clean(): void {
		$inspector = new RequestInspector();
		self::assertSame( 'observe', $inspector->inspect( array( 'q' => array( 'x' => '../private' ) ), false )['state'] );
		self::assertSame( 'partial', $inspector->inspect( array( 'q' => str_repeat( 'a', 9000 ) ), false )['state'] );
	}
}
