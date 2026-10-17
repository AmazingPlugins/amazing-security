<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Passkeys;

defined( 'ABSPATH' ) || exit;

final class PasskeyPolicy {
	public const OPTION = 'amsec_passkey_policy';
	public function read( mixed $raw ): ?array {
		if ( null === $raw ) {
			return array(
				'version'  => 1,
				'enabled'  => false,
				'revision' => str_repeat( '0', 32 ),
			); }
		$s = PasskeyState::object( $raw, 2048, array( 'version', 'enabled', 'revision' ) );
		return null !== $s && 1 === $s['version'] && is_bool( $s['enabled'] ) && PasskeyState::hex( $s['revision'], 32 ) ? $s : null;
	}
	public function fingerprint( mixed $raw ): string {
		return hash( 'sha256', is_string( $raw ) ? $raw : 'amsec-passkey-missing' );
	}
}
