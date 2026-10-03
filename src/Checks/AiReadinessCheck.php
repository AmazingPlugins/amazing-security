<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Checks;

use AmazingPlugins\Security\Findings\CheckResult;
use AmazingPlugins\Security\Findings\State;
use AmazingPlugins\Security\Scan\ScanContext;
use AmazingPlugins\Security\Scan\SecurityCheck;
use Closure;
use DateTimeImmutable;
use DateTimeZone;
use Throwable;

/** Reports application passwords, assistant access, and an llms.txt guide. It does not change them. */
final class AiReadinessCheck implements SecurityCheck {
	private const SOURCE = 'https://developer.wordpress.org/advanced-administration/security/hardening/';
	private readonly Closure $read;

	public function __construct( callable $read ) {
		$this->read = Closure::fromCallable( $read );
	}

	public function id(): string {
		return 'ai-readiness';
	}

	public function run( ScanContext $context ): array {
		try {
			$snapshot = ( $this->read )();
		} catch ( Throwable ) {
			$snapshot = array();
		}
		if ( ! is_array( $snapshot ) ) {
			$snapshot = array();
		}
		$passwords = self::choice( $snapshot['app_passwords'] ?? null, array( 'open', 'closed', 'plugin-off' ) );
		$assistant = self::choice( $snapshot['assistant'] ?? null, array( 'on', 'off' ) );
		$ready     = self::choice( $snapshot['assistant_ready'] ?? null, array( 'yes', 'no' ) );
		$guide     = self::choice( $snapshot['guide'] ?? null, array( 'present', 'absent' ) );
		$state     = match ( true ) {
			'open' === $passwords || 'on' === $assistant => State::WARN,
			( 'closed' === $passwords || 'plugin-off' === $passwords ) && 'off' === $assistant => State::PASS,
			default => State::UNKNOWN,
		};
		return array(
			new CheckResult(
				$this->id(),
				$state,
				self::summary( $passwords, $assistant, $ready, $guide ),
				self::SOURCE,
				new DateTimeImmutable( 'now', new DateTimeZone( 'UTC' ) ),
				State::UNKNOWN === $state ? 'low' : 'medium',
				State::UNKNOWN === $state ? 'unavailable' : 'complete',
				array(
					'app_passwords'   => $passwords,
					'assistant'       => $assistant,
					'assistant_ready' => $ready,
					'guide'           => $guide,
				)
			),
		);
	}

	/** @return array{app_passwords: string, assistant: string, assistant_ready: string, guide: string} */
	public static function wordpressSnapshot(): array {
		$paused    = function_exists( 'get_option' ) && '1' === get_option( 'amsec_disable_application_passwords', '0' );
		$available = function_exists( 'wp_is_application_passwords_available' ) ? wp_is_application_passwords_available() : null;
		$setting   = get_option( 'amazing_security_mcp_enabled', null );
		return array(
			'app_passwords'   => $paused ? 'plugin-off' : ( true === $available ? 'open' : ( false === $available ? 'closed' : 'unknown' ) ),
			'assistant'       => self::assistant( $setting ),
			'assistant_ready' => self::ready(),
			'guide'           => self::guide(),
		);
	}

	/** @param array<int, string> $allowed */
	private static function choice( mixed $value, array $allowed ): string {
		return is_string( $value ) && in_array( $value, $allowed, true ) ? $value : 'unknown';
	}

	private static function assistant( mixed $setting ): string {
		if ( null === $setting || false === $setting || '' === $setting || '0' === $setting || 0 === $setting ) {
			return 'off';
		}
		return true === $setting || 1 === $setting || '1' === $setting ? 'on' : 'unknown';
	}

	private static function ready(): string {
		if ( ! function_exists( 'is_plugin_active' ) ) {
			return 'unknown';
		}
		return function_exists( 'wp_register_ability' ) && is_plugin_active( 'mcp-adapter/mcp-adapter.php' ) ? 'yes' : 'no';
	}

	private static function guide(): string {
		if ( ! defined( 'ABSPATH' ) ) {
			return 'unknown';
		}
		$path = ABSPATH . 'llms.txt';
		if ( is_link( $path ) ) {
			return 'unknown';
		}
		if ( ! file_exists( $path ) ) {
			return 'absent';
		}
		if ( ! is_file( $path ) ) {
			return 'unknown';
		}
		$size = filesize( $path );
		return false !== $size && $size <= 65536 ? 'present' : 'unknown';
	}

	private static function summary( string $passwords, string $assistant, string $ready, string $guide ): string {
		$tools = match ( $passwords ) {
			'open' => 'Application passwords are available, so a tool can sign in without the login form. You can pause them here. Saved passwords stay stored.',
			'plugin-off' => 'Application passwords are paused by this plugin. Saved passwords stay stored and work again if you allow them.',
			'closed' => 'Application passwords are turned off.',
			default => 'Application password availability could not be read.',
		};
		$access = match ( true ) {
			'on' === $assistant => 'AI assistant access is on.',
			'off' === $assistant && 'yes' === $ready => 'AI assistant access is off. This site can connect an assistant when you turn that on.',
			'off' === $assistant && 'no' === $ready => 'AI assistant access is off. This site is not ready to connect an assistant yet.',
			'off' === $assistant => 'AI assistant access is off. Assistant readiness could not be read.',
			default => 'AI assistant access could not be read.',
		};
		$file = match ( $guide ) {
			'present' => 'An llms.txt guide is published for AI readers.',
			'absent' => 'No llms.txt guide is published.',
			default => 'The llms.txt guide could not be read.',
		};
		return $tools . ' ' . $access . ' ' . $file . ' This check does not change those settings and does not send the site to a model.';
	}
}
