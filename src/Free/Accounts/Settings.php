<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Free\Accounts;

defined( 'ABSPATH' ) || exit;

/** Posted account settings. Does not read or write the common-password switch. */
final class Settings {
	public const ERASE = 'amsec_login_erase_on_uninstall';

	/**
	 * @param array<string, mixed> $post
	 * @return array<string, string>
	 */
	public static function fromPost( array $post ): array {
		return array(
			IdleLogout::OPTION           => (string) IdleLogout::minutes( $post[ IdleLogout::OPTION ] ?? '0' ),
			RegistrationApproval::OPTION => self::flag( $post[ RegistrationApproval::OPTION ] ?? '0' ),
			EmailFactor::OPTION          => self::flag( $post[ EmailFactor::OPTION ] ?? '0' ),
			LoginChallenge::OPTION       => self::flag( $post[ LoginChallenge::OPTION ] ?? '0' ),
			self::ERASE                  => self::flag( $post[ self::ERASE ] ?? '0' ),
		);
	}

	public static function flag( mixed $value ): string {
		return '1' === (string) $value ? '1' : '0';
	}
}
