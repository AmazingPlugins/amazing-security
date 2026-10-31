<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit;

use AmazingPlugins\Security\Checks\AdminAccountsCheck;
use AmazingPlugins\Security\Checks\DebugDisplayCheck;
use AmazingPlugins\Security\Checks\FileEditorCheck;
use AmazingPlugins\Security\Checks\HttpsAdminCheck;
use AmazingPlugins\Security\Checks\UpdatePostureCheck;
use AmazingPlugins\Security\Checks\Values;
use AmazingPlugins\Security\Scan\ScanContext;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class ChecksTest extends TestCase {
	public static function cases(): array {
		return array(
			'update'      => array( UpdatePostureCheck::class, 'coreUpdateAvailable' ),
			'debug'       => array( DebugDisplayCheck::class, 'debugDisplayed' ),
			'file editor' => array( FileEditorCheck::class, 'fileEditorDisabled' ),
			'HTTPS'       => array( HttpsAdminCheck::class, 'adminUsesHttps' ),
			'admin login' => array( AdminAccountsCheck::class, 'hasDefaultAdminLogin' ),
		);
	}

	#[DataProvider( 'cases' )]
	public function test_unreadable_value_is_unknown( string $checkClass, string $method ): void {
		$values = $this->createMock( Values::class );
		$values->method( $method )->willReturn( null );
		$result = ( new $checkClass( $values ) )->run( new ScanContext() )[0];
		self::assertSame( 'unknown', $result->state );
		self::assertSame( 'unavailable', $result->coverage );
	}

	#[DataProvider( 'cases' )]
	public function test_observed_value_has_a_source_and_time( string $checkClass, string $method ): void {
		$values = $this->createMock( Values::class );
		$values->method( $method )->willReturn( true );
		$result = ( new $checkClass( $values ) )->run( new ScanContext() )[0];
		self::assertContains( $result->state, array( 'pass', 'warn' ) );
		self::assertStringStartsWith( 'https://developer.wordpress.org/', $result->sourceUrl );
		self::assertSame( 'complete', $result->coverage );
	}

	#[DataProvider( 'cases' )]
	public function test_opposite_observed_value_still_has_complete_coverage( string $checkClass, string $method ): void {
		$values = $this->createMock( Values::class );
		$values->method( $method )->willReturn( false );
		$result = ( new $checkClass( $values ) )->run( new ScanContext() )[0];
		self::assertContains( $result->state, array( 'pass', 'warn' ) );
		self::assertSame( 'complete', $result->coverage );
	}

	public function test_warnings_name_the_first_change_without_a_php_constant(): void {
		$values = $this->createMock( Values::class );
		$values->method( 'adminUsesHttps' )->willReturn( false );
		$values->method( 'coreUpdateAvailable' )->willReturn( true );
		$values->method( 'hasDefaultAdminLogin' )->willReturn( true );
		$values->method( 'debugDisplayed' )->willReturn( true );
		$values->method( 'fileEditorDisabled' )->willReturn( false );
		$summaries = array(
			( new HttpsAdminCheck( $values ) )->run( new ScanContext() )[0]->summary,
			( new UpdatePostureCheck( $values ) )->run( new ScanContext() )[0]->summary,
			( new AdminAccountsCheck( $values ) )->run( new ScanContext() )[0]->summary,
			( new DebugDisplayCheck( $values ) )->run( new ScanContext() )[0]->summary,
			( new FileEditorCheck( $values ) )->run( new ScanContext() )[0]->summary,
		);
		self::assertSame(
			array(
				'The admin address is not using HTTPS. Turn on HTTPS for this site before you change other security settings.',
				'A WordPress update is waiting. Open Dashboard, then Updates, and review it.',
				'An administrator uses admin as a login or as the name shown on the site. Open Users and change it.',
				'Visitors may see WordPress error details. You can hide them for requests that load this plugin. This plugin will not edit wp-config.php.',
				'People can edit theme and plugin files in wp-admin. Turn that editor off so a signed-in session cannot change PHP from the browser.',
			),
			$summaries
		);
		self::assertStringNotContainsString( 'DISALLOW_FILE_EDIT', implode( ' ', $summaries ) );
	}
}
