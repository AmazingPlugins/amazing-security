<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Tests\Unit\Sessions;

use AmazingPlugins\Security\Sessions\SessionPolicy;
use PHPUnit\Framework\TestCase;
final class SessionPolicyTest extends TestCase {
	public function test_approving_cookie_tokens_must_match(): void {
		self::assertTrue( SessionPolicy::matchingTokens( 'same', 'same' ) );
		self::assertFalse( SessionPolicy::matchingTokens( 'admin-session', 'other-session' ) );
		self::assertFalse( SessionPolicy::matchingTokens( '', '' ) );
	}
	public function test_only_an_administrator_or_the_account_owner_can_view_sessions(): void {
		self::assertTrue( SessionPolicy::canView( true, 2, 5 ) );
		self::assertTrue( SessionPolicy::canView( false, 5, 5 ) );
		self::assertFalse( SessionPolicy::canView( false, 2, 5 ) );
		self::assertFalse( SessionPolicy::canView( true, 0, 5 ) );
		self::assertFalse( SessionPolicy::canView( false, 5, 0 ) );
	}
	public function test_every_precondition_is_required(): void {
		self::assertTrue( SessionPolicy::allowed( true, true, true, true, true, true ) );
		for ( $i = 0;$i < 6;$i++ ) {
			$args       = array_fill( 0, 6, true );
			$args[ $i ] = false;
			self::assertFalse( SessionPolicy::allowed( ...$args ) );}
	}
	public function test_view_keeps_browser_details_and_drops_the_token(): void {
		$rows = SessionPolicy::safeRows(
			array(
				array(
					'login'      => 100,
					'expiration' => 200,
					'ip'         => '203.0.113.10',
					'ua'         => "Chrome\nsecret",
					'token'      => 'secret',
				),
			),
			array(
				'login'      => 100,
				'expiration' => 200,
				'ip'         => '203.0.113.10',
				'ua'         => "Chrome\nsecret",
			)
		);
		self::assertSame(
			array(
				array(
					'login'      => 100,
					'expiration' => 200,
					'ip'         => '203.0.113.10',
					'ua'         => 'Chrome secret',
					'current'    => true,
				),
			),
			$rows
		);
		self::assertArrayNotHasKey( 'token', $rows[0] );
		self::assertSame(
			'',
			SessionPolicy::safeRows(
				array(
					array(
						'login'      => 1,
						'expiration' => 2,
						'ip'         => 'secret-ip',
					),
				)
			)[0]['ip']
		);
		self::assertCount(
			50,
			SessionPolicy::safeRows(
				array_fill(
					0,
					60,
					array(
						'login'      => 100,
						'expiration' => 200,
					)
				)
			)
		);
		$many = array();
		for ( $i = 0;$i < 55;$i++ ) {
			$many[ 'v' . $i ] = array(
				'login'      => $i,
				'expiration' => 9,
				'ip'         => '203.0.113.10',
				'ua'         => 'curl/8.7.1',
			);}
		$many['now'] = array(
			'login'      => 3,
			'expiration' => 8,
			'ip'         => '198.51.100.8',
			'ua'         => 'curl/9',
		);
		$ordered     = SessionPolicy::safeRows( $many, $many['now'] );
		self::assertTrue( $ordered[0]['current'] );
		self::assertSame( 54, $ordered[1]['login'] );
		self::assertCount( 50, $ordered );
		$ref = SessionPolicy::ref( $rows[0] );
		self::assertSame( 16, strlen( $ref ) );
		self::assertSame( $rows[0], SessionPolicy::rowFor( $rows, $ref ) );
		self::assertNull( SessionPolicy::rowFor( $rows, '0000000000000000' ) );
		self::assertStringNotContainsString( 'secret', $ref );
	}
}
