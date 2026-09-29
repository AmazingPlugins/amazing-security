<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Alerts;

use AmazingPlugins\Security\Admin\AlertSettingsAction;
use PHPUnit\Framework\TestCase;

final class AlertSettingsActionTest extends TestCase {
	public function test_accepts_only_explicit_on_or_off(): void {
		self::assertTrue( AlertSettingsAction::parse( array( 'enabled' => '1' ) ) );
		self::assertFalse( AlertSettingsAction::parse( array( 'enabled' => '0' ) ) );
		$this->expectException( \InvalidArgumentException::class );
		AlertSettingsAction::parse( array( 'enabled' => array( '1' ) ) );
	}
}
