<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Admin;

use AmazingPlugins\Security\Admin\AdminPage;
use AmazingPlugins\Security\Findings\CheckResult;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

final class StatusGroupTest extends TestCase {
	public function test_pass_is_success_and_unfinished_checks_stay_in_info(): void {
		$source   = 'https://developer.wordpress.org/advanced-administration/security/hardening/';
		$when     = new DateTimeImmutable( '2026-10-06T00:00:00Z' );
		$pass     = new CheckResult( 'https-admin', 'pass', 'HTTPS is on for wp-admin.', $source, $when, 'high', 'complete', array() );
		$fail     = new CheckResult( 'debug-display', 'fail', 'Error details are shown.', $source, $when, 'high', 'complete', array() );
		$critical = new CheckResult( 'authenticator-app', 'critical', 'No authenticator-app plugin was detected.', $source, $when, 'high', 'complete', array() );
		$warn     = new CheckResult( 'file-editor', 'warn', 'The file editor is on.', $source, $when, 'high', 'complete', array() );
		$info     = new CheckResult( 'known-holes', 'unknown', 'The check could not be confirmed.', $source, $when, 'low', 'unavailable', array() );
		$later    = new CheckResult( 'release-files', 'pass', 'The file check has not started.', $source, $when, 'low', 'partial', array( 'stored' => 'none' ) );

		self::assertSame( 'success', AdminPage::statusOf( $pass ) );
		self::assertSame( 'error', AdminPage::statusOf( $fail ) );
		self::assertSame( 'critical', AdminPage::statusOf( $critical ) );
		self::assertSame( 'warning', AdminPage::statusOf( $warn ) );
		self::assertSame( 'recommended', AdminPage::statusOf( $info ) );
		self::assertSame( 'recommended', AdminPage::statusOf( $later ) );
	}
}
