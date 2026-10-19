<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Login;

use AmazingPlugins\Security\Login\CommonPasswordHooks;
use PHPUnit\Framework\TestCase;

final class CommonPasswordHooksProfileTest extends TestCase {
	/** edit_user() hands this hook a stdClass. A WP_User type hint made every profile save a fatal error. */
	public function test_profile_accepts_the_stdclass_wordpress_passes(): void {
		$method = new \ReflectionMethod( CommonPasswordHooks::class, 'profile' );
		$type   = $method->getParameters()[2]->getType();
		self::assertSame( 'object', (string) $type );
	}
}
