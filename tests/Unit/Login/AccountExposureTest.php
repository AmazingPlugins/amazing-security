<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Login;

use AmazingPlugins\Security\Admin\StartHere;
use AmazingPlugins\Security\Checks\GapCheck;
use AmazingPlugins\Security\Login\AccountExposure;
use AmazingPlugins\Security\Scan\ScanContext;
use PHPUnit\Framework\TestCase;

final class AccountExposureTest extends TestCase {
	public function test_author_and_user_list_gates_stay_off_until_enabled(): void {
		self::assertSame( 'allow', AccountExposure::authorDecision( false, false, '1', '' ) );
		self::assertSame( 'allow', AccountExposure::authorDecision( true, true, '1', 'admin' ) );
		self::assertSame( 'allow', AccountExposure::authorDecision( true, false, '', '' ) );
		self::assertSame( 'redirect', AccountExposure::authorDecision( true, false, '1', '' ) );
		self::assertSame( 'redirect', AccountExposure::authorDecision( true, false, '', 'admin' ) );

		self::assertSame( 'allow', AccountExposure::restDecision( true, false, '/wp/v2/posts', 'GET' ) );
		self::assertSame( 'allow', AccountExposure::restDecision( true, true, '/wp/v2/users', 'GET' ) );
		self::assertSame( 'allow', AccountExposure::restDecision( false, false, '/wp/v2/users', 'GET' ) );
		self::assertSame( 'allow', AccountExposure::restDecision( true, false, '/wp/v2/users/me', 'GET' ) );
		self::assertSame( 'allow', AccountExposure::restDecision( true, false, '/wp/v2/users', 'POST' ) );
		self::assertSame( 'deny', AccountExposure::restDecision( true, false, '/wp/v2/users', 'GET' ) );
		self::assertSame( 'deny', AccountExposure::restDecision( true, false, '/wp/v2/users/2', 'GET' ) );

		$authors = ( new GapCheck( 'author-archives', static fn(): string => '0' ) )->run( new ScanContext() )[0];
		$hidden  = ( new GapCheck( 'author-archives', static fn(): string => '1' ) )->run( new ScanContext() )[0];
		$users   = ( new GapCheck( 'rest-user-list', static fn(): string => '0' ) )->run( new ScanContext() )[0];
		$closed  = ( new GapCheck( 'rest-user-list', static fn(): string => '1' ) )->run( new ScanContext() )[0];

		self::assertSame( 'warn', $authors->state );
		self::assertStringContainsString( 'does not send site data', $authors->summary );
		self::assertStringNotContainsString( 'safe', $authors->summary );
		self::assertSame( 'enable-author-archives', StartHere::control( $authors )['operation'] );
		self::assertSame( 'pass', $hidden->state );
		self::assertSame( 'disable-author-archives', StartHere::control( $hidden )['operation'] );

		self::assertSame( 'warn', $users->state );
		self::assertStringContainsString( 'does not send site data', $users->summary );
		self::assertStringNotContainsString( 'safe', $users->summary );
		self::assertSame( 'enable-rest-users', StartHere::control( $users )['operation'] );
		self::assertSame( 'pass', $closed->state );
		self::assertSame( 'disable-rest-users', StartHere::control( $closed )['operation'] );
	}
}
