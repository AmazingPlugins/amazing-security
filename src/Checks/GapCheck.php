<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Checks;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Findings\CheckResult;
use AmazingPlugins\Security\Findings\State;
use AmazingPlugins\Security\Scan\ScanContext;
use AmazingPlugins\Security\Scan\SecurityCheck;
use Closure;
use DateTimeImmutable;
use DateTimeZone;
use Throwable;

/** Reports a local login gate. It does not contact a provider. */
final class GapCheck implements SecurityCheck {
	private const SOURCE = 'https://developer.wordpress.org/advanced-administration/security/hardening/';
	private readonly Closure $readStatus;

	public function __construct( private readonly string $checkId, ?callable $readStatus = null ) {
		$this->readStatus = Closure::fromCallable( $readStatus ?? static fn(): string => '0' );
	}

	public function id(): string {
		return $this->checkId;
	}

	public function run( ScanContext $context ): array {
		try {
			$status = ( $this->readStatus )();
		} catch ( Throwable ) {
			$status = null;
		}
		$known = '1' === $status ? 'on' : ( is_string( $status ) ? 'off' : '' );
		$state = match ( $known ) {
			'on' => State::PASS,
			'off' => State::WARN,
			default => State::UNKNOWN,
		};
		$summary = match ( $this->checkId . ':' . $known ) {
			'captcha-login:on' => __( 'The WordPress login form asks for a sign-in confirmation. This is not a CAPTCHA service, and this check does not send login attempts anywhere.', 'amazing-security' ),
			'captcha-login:off' => __( 'Login CAPTCHA is not set up. You can turn on a local sign-in confirmation for the WordPress login form. This check does not send login attempts anywhere.', 'amazing-security' ),
			'compromised-passwords:on' => __( 'New and reset passwords are compared with a short local list. A breach-list check may send a hash prefix, and this check does not send passwords anywhere. Existing sign-in is not blocked.', 'amazing-security' ),
			'compromised-passwords:off' => __( 'Compromised-password checks are not set up. You can turn on a short local list and a breach-list prefix check. This check does not send passwords anywhere.', 'amazing-security' ),
			'login-hints:on' => __( 'The WordPress login form uses one message for a wrong username and a wrong password. This check does not send login attempts anywhere.', 'amazing-security' ),
			'login-hints:off' => __( 'The WordPress login form says whether a username exists. You can use one message for a wrong username and a wrong password. This check does not send login attempts anywhere.', 'amazing-security' ),
			'author-archives:on' => __( 'Logged-out visitors are sent away from author pages. This check does not send site data anywhere.', 'amazing-security' ),
			'author-archives:off' => __( 'Author pages can show a login name. You can send logged-out visitors away from those pages. This check does not send site data anywhere.', 'amazing-security' ),
			'rest-user-list:on' => __( 'The REST user list requires a logged-in account. This check does not send site data anywhere.', 'amazing-security' ),
			'rest-user-list:off' => __( 'The public REST user list can show login names. You can require a logged-in account for that list. This check does not send site data anywhere.', 'amazing-security' ),
			'version-tag:on' => __( 'The WordPress generator tag is hidden. This check does not change that setting.', 'amazing-security' ),
			'version-tag:off' => __( 'WordPress shows its version in the generator tag. You can hide that tag. This check does not change that setting.', 'amazing-security' ),
			'discovery-links:on' => __( 'Really Simple Discovery and Windows Live Writer links are removed. This check does not change that setting.', 'amazing-security' ),
			'discovery-links:off' => __( 'Really Simple Discovery and Windows Live Writer links are public. You can remove those two links. This check does not change that setting.', 'amazing-security' ),
			default => __( 'This check could not be read. This check does not send site data anywhere.', 'amazing-security' ),
		};
		return array(
			new CheckResult( $this->id(), $state, $summary, self::SOURCE, new DateTimeImmutable( 'now', new DateTimeZone( 'UTC' ) ), State::UNKNOWN === $state ? 'low' : 'medium', State::UNKNOWN === $state ? 'unavailable' : 'complete', array( 'status' => '' !== $known ? $known : 'unknown' ) ),
		);
	}
}
