<?php
namespace AmazingPlugins\Security\Tests\Unit\Login;

use AmazingPlugins\Security\Login\BreachedPasswords;
use AmazingPlugins\Security\Login\RequiredTotpPolicy;
use AmazingPlugins\Security\Login\RequiredTotpState;
use PHPUnit\Framework\TestCase;
final class RequiredTotpStateTest extends TestCase {
	public function test_grace_has_exact_expiry_and_generation_binding(): void {
		$generation = str_repeat( 'a', 32 );
		$record     = array(
			'generation' => $generation,
			'deadline'   => 1000,
		);
		self::assertSame( 'grace', RequiredTotpState::evaluate( $record, $generation, 999 ) );
		self::assertSame( 'expired', RequiredTotpState::evaluate( $record, $generation, 1000 ) );
		self::assertSame( 'new', RequiredTotpState::evaluate( $record, str_repeat( 'b', 32 ), 1000 ) );
	}
	public function test_editor_coverage_and_breach_prefix_stay_narrow(): void {
		self::assertTrue( RequiredTotpPolicy::coveredAccount( true, array() ) );
		self::assertTrue( RequiredTotpPolicy::coveredAccount( false, array( 'editor' ) ) );
		self::assertFalse( RequiredTotpPolicy::coveredAccount( false, array( 'author' ) ) );
		self::assertFalse( RequiredTotpPolicy::coveredAccount( false, array( 'subscriber' ) ) );
		$suffix = str_repeat( 'A', 35 );
		self::assertTrue( BreachedPasswords::matchesSuffix( $suffix, $suffix . ':1' ) );
		self::assertFalse( BreachedPasswords::matchesSuffix( $suffix, str_repeat( 'B', 35 ) . ':1' ) );
		self::assertFalse( BreachedPasswords::matchesSuffix( 'short', $suffix . ':1' ) );
	}
	public function test_corruption_cannot_repeatedly_grant_a_new_grace_period(): void {
		$generation = str_repeat( 'a', 32 );
		self::assertSame( 'new', RequiredTotpState::evaluate( '', $generation, 100 ) );
		foreach ( array(
			array(),
			array( 'generation' => $generation ),
			array(
				'generation' => $generation,
				'deadline'   => '1000',
			),
			array(
				'generation' => $generation,
				'deadline'   => 0,
			),
			array(
				'generation' => 'bad',
				'deadline'   => 1000,
			),
		) as $bad ) {
			self::assertSame( 'unavailable', RequiredTotpState::evaluate( $bad, $generation, 100 ) );}
	}
}
