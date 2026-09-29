<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit;

use AmazingPlugins\Security\Fixes\RecipeCatalog;
use PHPUnit\Framework\TestCase;

final class FixRecipeTest extends TestCase {
	public function test_only_the_two_staged_login_rate_transitions_exist(): void {
		$recipes = new RecipeCatalog();
		self::assertSame( array( 'before' => 'off', 'after' => 'observe' ), $recipes->transition( 'login-rate-observe', 'off' ) );
		self::assertSame( array( 'before' => 'observe', 'after' => 'block' ), $recipes->transition( 'login-rate-block', 'observe' ) );
		self::assertNull( $recipes->transition( 'login-rate-block', 'off' ) );
		self::assertNull( $recipes->transition( 'login-rate-observe', 'block' ) );
		self::assertNull( $recipes->transition( 'file-delete', 'off' ) );
	}
}
