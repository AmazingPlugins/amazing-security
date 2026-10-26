<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Checks;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Findings\CheckResult;
use AmazingPlugins\Security\Findings\State;
use AmazingPlugins\Security\Login\AuthFactorDetector;
use AmazingPlugins\Security\Login\AuthFactorStatus;
use AmazingPlugins\Security\Scan\ScanContext;
use AmazingPlugins\Security\Scan\SecurityCheck;
use Closure;
use DateTimeImmutable;
use DateTimeZone;
use Throwable;

/** Reports third-party authenticator / passkey presence. Does not enroll devices. */
final class AuthFactorCheck implements SecurityCheck {
	private const SOURCE = 'https://wordpress.org/plugins/two-factor/';
	private readonly Closure $read;

	/**
	 * @param callable():array{state:string,provider:string,suggest_slug:string,suggest_name:string} $read
	 */
	public function __construct( private readonly string $checkId, ?callable $read = null ) {
		$this->read = Closure::fromCallable(
			$read ?? static function () use ( $checkId ): array {
				$detector = AuthFactorDetector::fromWordPress();
				$userId   = function_exists( 'get_current_user_id' ) ? get_current_user_id() : 0;
				return 'passkeys-status' === $checkId ? $detector->passkeys( $userId ) : $detector->totp( $userId );
			}
		);
	}

	public function id(): string {
		return $this->checkId;
	}

	public function run( ScanContext $context ): array {
		unset( $context );
		try {
			$factor = ( $this->read )();
		} catch ( Throwable ) {
			$factor = array(
				'state'        => AuthFactorStatus::MISSING,
				'provider'     => '',
				'suggest_slug' => 'two-factor',
				'suggest_name' => 'Two Factor',
			);
		}
		$stateKey = is_string( $factor['state'] ?? null ) ? $factor['state'] : AuthFactorStatus::MISSING;
		$state    = match ( $stateKey ) {
			AuthFactorStatus::ACTIVE    => State::PASS,
			AuthFactorStatus::AVAILABLE => State::WARN,
			default                     => State::CRITICAL,
		};
		$kind     = 'passkeys-status' === $this->checkId ? 'passkeys' : 'authenticator';
		$provider = is_string( $factor['provider'] ?? null ) && '' !== $factor['provider'] ? $factor['provider'] : __( 'That plugin', 'amazingplugins-security-scanner' );
		$summary  = match ( $kind . ':' . $stateKey ) {
			'authenticator:active' => $provider . ' is handling authenticator codes for this account. AmazingPlugins Security Scanner does not store backup codes; manage enrollment there.',
			'authenticator:available' => $provider . ' is installed but not in use for this account. Turn it on there. AmazingPlugins Security Scanner only reports status.',
			'authenticator:missing' => __( 'No authenticator-app plugin was detected. Install a dedicated plugin such as Two Factor if you want app codes. AmazingPlugins Security Scanner does not enroll devices.', 'amazingplugins-security-scanner' ),
			'passkeys:active' => $provider . ' is handling passkeys for this account. Manage devices there. AmazingPlugins Security Scanner does not enroll passkeys.',
			'passkeys:available' => $provider . ' is installed but not in use for this account. Turn it on there. AmazingPlugins Security Scanner only reports status.',
			'passkeys:missing' => __( 'No passkey plugin was detected. Install a dedicated plugin such as Two Factor if you want passkeys. AmazingPlugins Security Scanner does not enroll devices.', 'amazingplugins-security-scanner' ),
			default => __( 'Authenticator status could not be read. AmazingPlugins Security Scanner does not enroll devices.', 'amazingplugins-security-scanner' ),
		};
		$confidence = match ( $state ) {
			State::CRITICAL => 'high',
			State::WARN => 'medium',
			default => 'low',
		};
		return array(
			new CheckResult(
				$this->id(),
				$state,
				$summary,
				self::SOURCE,
				new DateTimeImmutable( 'now', new DateTimeZone( 'UTC' ) ),
				$confidence,
				'complete',
				array(
					'status'   => $stateKey,
					'provider' => is_string( $factor['provider'] ?? null ) ? $factor['provider'] : '',
				)
			),
		);
	}
}
