<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Fixes;

use AmazingPlugins\Security\Fixes\ApprovedSetting;
use PHPUnit\Framework\TestCase;

final class ApprovedSettingTest extends TestCase {
	public function test_pingbacks_close_only_from_open(): void {
		self::assertSame( 'closed', ApprovedSetting::pingStatus( 'open' ) );
		self::assertSame( '', ApprovedSetting::pingStatus( 'closed' ) );
		self::assertSame( '', ApprovedSetting::pingStatus( '' ) );
	}

	public function test_file_editor_is_refused_when_the_constant_exists(): void {
		self::assertSame( '1', ApprovedSetting::fileEditorOption( false ) );
		self::assertSame( '', ApprovedSetting::fileEditorOption( true ) );
		self::assertSame( '0', ApprovedSetting::debugRestore( '1' ) );
		self::assertSame( '', ApprovedSetting::debugRestore( '0' ) );
		self::assertSame( '1', ApprovedSetting::debugHide( '0' ) );
		self::assertSame( '', ApprovedSetting::debugHide( '1' ) );
		self::assertSame( '0', ApprovedSetting::fileEditorRestore( '1' ) );
		self::assertSame( '', ApprovedSetting::fileEditorRestore( '0' ) );
		self::assertSame( '1', ApprovedSetting::gateOn( '0' ) );
		self::assertSame( '', ApprovedSetting::gateOn( '1' ) );
		self::assertSame( '0', ApprovedSetting::gateOff( '1' ) );
		self::assertSame( '', ApprovedSetting::gateOff( '0' ) );
	}
}
