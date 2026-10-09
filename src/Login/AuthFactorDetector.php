<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Login;

/**
 * Detects third-party passkey / TOTP providers. Amazing Security’s own stacks do not count.
 *
 * @phpstan-type FactorResult array{state:string,provider:string,suggest_slug:string,suggest_name:string}
 */
final class AuthFactorDetector {
	/** @var array<string, string> */
	private const TOTP_PLUGINS = array(
		'two-factor/two-factor.php' => 'Two Factor',
		'wp-2fa/wp-2fa.php'         => 'WP 2FA',
		'miniorange-2-factor-authentication/miniorange_2_factor_settings.php' => 'miniOrange 2FA',
	);

	/** @var array<string, string> */
	private const PASSKEY_PLUGINS = array(
		'two-factor/two-factor.php' => 'Two Factor',
	);

	/**
	 * @param list<string>       $activePlugins
	 * @param callable(int,string):mixed $userMeta
	 */
	public function __construct( private readonly array $activePlugins, private $userMeta ) {}

	public static function fromWordPress(): self {
		$active = get_option( 'active_plugins', array() );
		$active = is_array( $active ) ? array_values( array_filter( $active, 'is_string' ) ) : array();
		return new self(
			$active,
			static fn ( int $userId, string $key ): mixed => get_user_meta( $userId, $key, true )
		);
	}

	/** @return FactorResult */
	public function totp( int $userId ): array {
		$hit = $this->firstActive( self::TOTP_PLUGINS );
		if ( null === $hit ) {
			return $this->missing( 'two-factor', 'Two Factor' );
		}
		[ $slug, $label ] = $hit;
		$inUse            = $this->totpInUse( $userId, $slug );
		return array(
			'state'        => AuthFactorStatus::resolve( true, $inUse ),
			'provider'     => $label,
			'suggest_slug' => 'two-factor',
			'suggest_name' => 'Two Factor',
		);
	}

	/** @return FactorResult */
	public function passkeys( int $userId ): array {
		$hit = $this->firstActive( self::PASSKEY_PLUGINS );
		if ( null === $hit ) {
			return $this->missing( 'two-factor', 'Two Factor' );
		}
		[ $slug, $label ] = $hit;
		$inUse            = $this->passkeyInUse( $userId, $slug );
		return array(
			'state'        => AuthFactorStatus::resolve( true, $inUse ),
			'provider'     => $label,
			'suggest_slug' => 'two-factor',
			'suggest_name' => 'Two Factor',
		);
	}

	/** @return FactorResult */
	private function missing( string $slug, string $name ): array {
		return array(
			'state'        => AuthFactorStatus::MISSING,
			'provider'     => '',
			'suggest_slug' => $slug,
			'suggest_name' => $name,
		);
	}

	/**
	 * @param array<string, string> $map
	 * @return array{0:string,1:string}|null
	 */
	private function firstActive( array $map ): ?array {
		foreach ( $map as $file => $label ) {
			if ( in_array( $file, $this->activePlugins, true ) ) {
				return array( $file, $label );
			}
		}
		return null;
	}

	private function totpInUse( int $userId, string $plugin ): bool {
		if ( 'two-factor/two-factor.php' === $plugin ) {
			$providers = ( $this->userMeta )( $userId, '_two_factor_enabled_providers' );
			return is_array( $providers ) && array() !== $providers;
		}
		if ( 'wp-2fa/wp-2fa.php' === $plugin ) {
			$enabled = ( $this->userMeta )( $userId, 'wp_2fa_enabled_methods' );
			return ( is_string( $enabled ) && '' !== $enabled ) || ( is_array( $enabled ) && array() !== $enabled );
		}
		// Prefer Available, off when the signal is unclear.
		return false;
	}

	private function passkeyInUse( int $userId, string $plugin ): bool {
		if ( 'two-factor/two-factor.php' !== $plugin ) {
			return false;
		}
		$providers = ( $this->userMeta )( $userId, '_two_factor_enabled_providers' );
		if ( ! is_array( $providers ) ) {
			return false;
		}
		foreach ( $providers as $provider ) {
			if ( ! is_string( $provider ) ) {
				continue;
			}
			$upper = strtoupper( $provider );
			if ( str_contains( $upper, 'FIDO' ) || str_contains( $upper, 'WEBAUTHN' ) || str_contains( $upper, 'U2F' ) ) {
				return true;
			}
		}
		return false;
	}
}
