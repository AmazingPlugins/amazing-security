<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Login;

use AmazingPlugins\Security\Login\AuthFactorDetector;
use AmazingPlugins\Security\Login\AuthFactorPanel;
use AmazingPlugins\Security\Login\AuthFactorStatus;
use PHPUnit\Framework\TestCase;

final class AuthFactorStatusTest extends TestCase {
	public function test_resolve_matrix(): void {
		self::assertSame( AuthFactorStatus::MISSING, AuthFactorStatus::resolve( false, false ) );
		self::assertSame( AuthFactorStatus::MISSING, AuthFactorStatus::resolve( false, true ) );
		self::assertSame( AuthFactorStatus::AVAILABLE, AuthFactorStatus::resolve( true, false ) );
		self::assertSame( AuthFactorStatus::ACTIVE, AuthFactorStatus::resolve( true, true ) );
	}

	public function test_detector_missing_without_plugins(): void {
		$detector = new AuthFactorDetector( array(), static fn (): mixed => null );
		$totp     = $detector->totp( 1 );
		$pass     = $detector->passkeys( 1 );
		self::assertSame( AuthFactorStatus::MISSING, $totp['state'] );
		self::assertSame( AuthFactorStatus::MISSING, $pass['state'] );
		self::assertSame( 'two-factor', $totp['suggest_slug'] );
	}

	public function test_detector_available_then_active_for_two_factor(): void {
		$meta     = array();
		$detector = new AuthFactorDetector(
			array( 'two-factor/two-factor.php' ),
			static function ( int $userId, string $key ) use ( &$meta ): mixed {
				return $meta[ $userId ][ $key ] ?? null;
			}
		);
		self::assertSame( AuthFactorStatus::AVAILABLE, $detector->totp( 7 )['state'] );
		self::assertSame( AuthFactorStatus::AVAILABLE, $detector->passkeys( 7 )['state'] );
		$meta[7]['_two_factor_enabled_providers'] = array( 'Two_Factor_Totp' );
		self::assertSame( AuthFactorStatus::ACTIVE, $detector->totp( 7 )['state'] );
		self::assertSame( AuthFactorStatus::AVAILABLE, $detector->passkeys( 7 )['state'] );
		$meta[7]['_two_factor_enabled_providers'] = array( 'Two_Factor_FIDO_U2F' );
		self::assertSame( AuthFactorStatus::ACTIVE, $detector->passkeys( 7 )['state'] );
	}

	public function test_panel_missing_has_suggestion_not_enroll_forms(): void {
		$html = AuthFactorPanel::html(
			'Authenticator app',
			array(
				'state'        => AuthFactorStatus::MISSING,
				'provider'     => '',
				'suggest_slug' => 'two-factor',
				'suggest_name' => 'Two Factor',
			),
			'https://wordpress.org/plugins/two-factor/'
		);
		self::assertStringContainsString( 'Not on this site', $html );
		self::assertStringContainsString( 'two-factor', $html );
		self::assertStringNotContainsString( 'amsec_totp_begin', $html );
		self::assertStringNotContainsString( 'Set up verification codes', $html );
		self::assertStringContainsString( 'View Two Factor on WordPress.org', $html );
	}

	public function test_panel_missing_links_to_plugin_search_when_allowed(): void {
		$html = AuthFactorPanel::html(
			'Authenticator app',
			array(
				'state'        => AuthFactorStatus::MISSING,
				'provider'     => '',
				'suggest_slug' => 'two-factor',
				'suggest_name' => 'Two Factor',
			),
			'https://example.test/wp-admin/plugin-install.php?s=two-factor&tab=search&type=term'
		);
		self::assertStringContainsString( '>Find Two Factor</a>', $html );
		self::assertStringContainsString( 'Install Now and Activate', $html );
	}

	public function test_panel_missing_but_installed_links_to_activate(): void {
		$html = AuthFactorPanel::html(
			'Authenticator app',
			array(
				'state'        => AuthFactorStatus::MISSING,
				'provider'     => '',
				'suggest_slug' => 'two-factor',
				'suggest_name' => 'Two Factor',
			),
			'https://example.test/wp-admin/plugins.php?plugin_status=inactive&s=two%20factor'
		);
		self::assertStringContainsString( '>Activate Two Factor</a>', $html );
		self::assertStringContainsString( 'Two Factor is installed but not active', $html );
	}

	public function test_panel_escapes_provider_label(): void {
		$html = AuthFactorPanel::html(
			'Passkeys',
			array(
				'state'        => AuthFactorStatus::ACTIVE,
				'provider'     => '<script>x</script>',
				'suggest_slug' => 'two-factor',
				'suggest_name' => 'Two Factor',
			),
			'https://wordpress.org/plugins/two-factor/'
		);
		self::assertStringContainsString( '&lt;script&gt;x&lt;/script&gt;', $html );
		self::assertStringNotContainsString( '<script>x</script>', $html );
	}
}
