<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Checks;

use AmazingPlugins\Security\Integrity\WordPressOptions;
use AmazingPlugins\Security\Findings\CheckResult;
use AmazingPlugins\Security\Findings\State;
use AmazingPlugins\Security\Network\NetworkPolicy;
use AmazingPlugins\Security\Proxy\ProxyPolicy;
use AmazingPlugins\Security\Rules\RuleCatalog;
use AmazingPlugins\Security\Schedule\LocalSchedule;
use AmazingPlugins\Security\Schedule\SuiteCycle;
use AmazingPlugins\Security\Sessions\SessionPolicy;
use AmazingPlugins\Security\Scan\ScanContext;
use AmazingPlugins\Security\Scan\SecurityCheck;
use AmazingPlugins\Security\Traffic\TrafficPolicy;
use Closure;
use DateTimeImmutable;
use DateTimeZone;
use Throwable;

/** Reports a stored local setting. It does not change that setting. */
final class SiteWatchCheck implements SecurityCheck {
	private const SOURCE    = 'https://developer.wordpress.org/advanced-administration/security/hardening/';
	private const COPY      = array(
		'finding-emails'    => array(
			'on'      => 'Finding emails are on.',
			'off'     => 'Finding emails are off.',
			'unknown' => 'The finding-email setting could not be read.',
		),
		'weekly-digest'     => array(
			'on'      => 'The weekly security digest is on.',
			'off'     => 'The weekly security digest is off.',
			'unknown' => 'The weekly digest setting could not be read.',
		),
		'traffic-history'   => array(
			'on'      => 'PHP traffic history is on. Visitor addresses are not stored.',
			'off'     => 'PHP traffic history is off. Visitor addresses are not stored.',
			'unknown' => 'The traffic-history setting could not be read.',
		),
		'network-controls'  => array(
			'off'     => 'Manual network blocks are off.',
			'observe' => 'Manual network controls are recording only.',
			'block'   => 'Manual network blocks are on. Review the address list.',
			'unknown' => 'The network control setting could not be read.',
		),
		'trusted-proxies'   => array(
			'off'     => 'Trusted proxy addresses are off.',
			'xff'     => 'Forwarded addresses are trusted for the saved proxy list.',
			'single'  => 'One forwarded header is trusted for the saved proxy list.',
			'unknown' => 'The trusted-proxy setting could not be read.',
		),
		'security-activity' => array(
			'on'      => 'Security activity is being recorded on this site.',
			'off'     => 'Security activity is not being recorded.',
			'unknown' => 'The security activity record could not be read.',
		),
		'code-baselines'    => array(
			'none'    => 'Custom code has no owner-approved baseline. A baseline does not prove that code is clean.',
			'stored'  => 'An owner-approved code baseline is stored. It does not prove that code is clean.',
			'preview' => 'A code baseline preview is waiting for approval. It does not prove that code is clean.',
			'unknown' => 'The stored code baseline could not be read.',
		),
		'account-sessions'  => array(
			'extra'   => 'The account that ran this check has another WordPress session.',
			'single'  => 'The account that ran this check has no extra WordPress session.',
			'unknown' => 'Account sessions could not be read.',
		),
		'daily-checks'      => array(
			'never'    => 'A daily local check has not been recorded yet.',
			'missed'   => 'A daily local check is overdue.',
			'partial'  => 'The last daily local check did not finish.',
			'complete' => 'A daily local check is recorded.',
			'unknown'  => 'The daily local check record could not be read.',
		),
		'daily-file-checks' => array(
			'never'    => 'A daily integrity and file check has not been recorded yet.',
			'partial'  => 'The last daily integrity and file check did not finish.',
			'running'  => 'A daily integrity and file check is still in progress.',
			'complete' => 'A daily integrity and file check is recorded.',
			'unknown'  => 'The daily integrity and file check record could not be read.',
		),
		'rule-review'       => array(
			'recent'  => 'Bundled rule metadata was reviewed within 90 days. This is not a malware feed.',
			'overdue' => 'Bundled rule metadata is older than 90 days. This is not a malware feed.',
			'unknown' => 'Bundled rule metadata could not be read. This is not a malware feed.',
		),
	);
	private const SUFFIX    = array(
		'account-sessions'  => ' This check does not revoke a session.',
		'daily-checks'      => ' This check does not start one.',
		'daily-file-checks' => ' This check does not start one.',
		'rule-review'       => ' This check does not download new rules.',
	);
	private const ATTENTION = array(
		'finding-emails'    => array( 'off' ),
		'weekly-digest'     => array( 'off' ),
		'traffic-history'   => array( 'off' ),
		'network-controls'  => array( 'observe', 'block' ),
		'trusted-proxies'   => array( 'xff', 'single' ),
		'security-activity' => array( 'off' ),
		'code-baselines'    => array( 'none', 'preview' ),
		'account-sessions'  => array( 'extra' ),
		'daily-checks'      => array( 'never', 'missed', 'partial' ),
		'daily-file-checks' => array( 'never', 'partial', 'running' ),
		'rule-review'       => array( 'overdue', 'unknown' ),
	);
	private readonly Closure $read;

	public function __construct( private readonly string $checkId, callable $read ) {
		$this->read = Closure::fromCallable( $read );
	}

	public function id(): string {
		return $this->checkId;
	}

	public function run( ScanContext $context ): array {
		try {
			$snapshot = ( $this->read )();
		} catch ( Throwable ) {
			$snapshot = array();
		}
		$status = is_array( $snapshot ) && is_string( $snapshot['status'] ?? null ) && isset( self::COPY[ $this->checkId ][ $snapshot['status'] ] ) ? $snapshot['status'] : 'unknown';
		$state  = match ( true ) {
			! isset( self::COPY[ $this->checkId ] ) || 'unknown' === $status => State::UNKNOWN,
			in_array( $status, self::ATTENTION[ $this->checkId ], true ) => State::WARN,
			default => State::PASS,
		};
		$line = self::COPY[ $this->checkId ][ $status ] ?? 'The stored setting could not be read.';
		return array(
			new CheckResult(
				$this->id(),
				$state,
				$line . ( self::SUFFIX[ $this->checkId ] ?? ' This check does not change that setting.' ),
				self::SOURCE,
				new DateTimeImmutable( 'now', new DateTimeZone( 'UTC' ) ),
				State::UNKNOWN === $state ? 'low' : 'medium',
				State::UNKNOWN === $state ? 'unavailable' : 'complete',
				array( 'status' => $status )
			),
		);
	}

	/** @return array{status: string} */
	public static function findingEmails(): array {
		return array( 'status' => self::emails( get_option( 'amsec_alerts_enabled', null ) ) );
	}

	/** @return array{status: string} */
	public static function weeklyDigest(): array {
		return array( 'status' => self::digest( get_option( 'amsec_digest_enabled', '0' ) ) );
	}

	/** @return array{status: string} */
	public static function trafficHistory(): array {
		return array( 'status' => self::traffic( get_option( 'amsec_traffic_policy', null ) ) );
	}

	/** @return array{status: string} */
	public static function networkControls(): array {
		return array( 'status' => self::network( get_option( 'amsec_network_policy', null ) ) );
	}

	/** @return array{status: string} */
	public static function trustedProxies(): array {
		return array( 'status' => self::proxies( get_option( 'amsec_proxy_policy', null ) ) );
	}

	/** @return array{status: string} */
	public static function securityActivity(): array {
		return array( 'status' => self::activity( get_option( 'amsec_activity_schema_version', null ) ) );
	}

	/** @return array{status: string} */
	public static function codeBaselines(): array {
		return array( 'status' => self::baselines( get_option( 'amsec_custom_baseline_state', null ) ) );
	}

	/** @return array{status: string} */
	public static function accountSessions(): array {
		if ( ! function_exists( 'get_current_user_id' ) || ! class_exists( 'WP_Session_Tokens' ) || get_current_user_id() < 1 ) {
			return array( 'status' => 'unknown' );
		}
		try {
			$rows = SessionPolicy::safeRows( \WP_Session_Tokens::get_instance( get_current_user_id() )->get_all() );
		} catch ( Throwable ) {
			return array( 'status' => 'unknown' );
		}
		return array( 'status' => count( $rows ) > 1 ? 'extra' : 'single' );
	}

	/** @return array{status: string} */
	public static function dailyChecks(): array {
		try {
			$status = ( new LocalSchedule( new WordPressOptions() ) )->status( time() );
		} catch ( Throwable ) {
			return array( 'status' => 'unknown' );
		}
		$state = is_string( $status['state'] ?? null ) ? $status['state'] : '';
		return array( 'status' => in_array( $state, array( 'never', 'missed', 'partial', 'complete' ), true ) ? $state : 'unknown' );
	}

	/** @return array{status: string} */
	public static function dailyFileChecks(): array {
		try {
			$status = ( new SuiteCycle( new WordPressOptions() ) )->status( time() );
		} catch ( Throwable ) {
			return array( 'status' => 'unknown' );
		}
		$state = is_string( $status['state'] ?? null ) ? $status['state'] : '';
		return array( 'status' => in_array( $state, array( 'never', 'partial', 'running', 'complete' ), true ) ? $state : 'unknown' );
	}

	/** @return array{status: string} */
	public static function ruleReview(): array {
		if ( ! defined( 'AMAZING_SECURITY_FILE' ) ) {
			return array( 'status' => 'unknown' );
		}
		try {
			$packs = ( new RuleCatalog( dirname( AMAZING_SECURITY_FILE ) ) )->status( time() );
		} catch ( Throwable ) {
			return array( 'status' => 'unknown' );
		}
		$states = array();
		foreach ( $packs as $pack ) {
			$states[] = is_array( $pack ) && is_string( $pack['status'] ?? null ) ? $pack['status'] : 'unknown';
		}
		if ( array() === $states || in_array( 'unknown', $states, true ) ) {
			return array( 'status' => 'unknown' );
		}
		return array( 'status' => in_array( 'overdue', $states, true ) ? 'overdue' : 'recent' );
	}

	public static function emails( mixed $raw ): string {
		if ( '0' === $raw || 0 === $raw ) {
			return 'off';
		}
		return null === $raw || false === $raw || '' === $raw || '1' === $raw || 1 === $raw || true === $raw ? 'on' : 'unknown';
	}

	public static function digest( mixed $raw ): string {
		if ( '1' === $raw || 1 === $raw || true === $raw ) {
			return 'on';
		}
		return null === $raw || false === $raw || '' === $raw || '0' === $raw || 0 === $raw ? 'off' : 'unknown';
	}

	public static function traffic( mixed $raw ): string {
		$policy = ( new TrafficPolicy() )->read( $raw );
		if ( ! is_array( $policy ) ) {
			return 'unknown';
		}
		return true === ( $policy['enabled'] ?? null ) ? 'on' : 'off';
	}

	public static function network( mixed $raw ): string {
		$policy = ( new NetworkPolicy() )->read( $raw );
		$mode   = is_array( $policy ) ? ( $policy['mode'] ?? '' ) : '';
		return is_string( $mode ) && in_array( $mode, array( 'off', 'observe', 'block' ), true ) ? $mode : 'unknown';
	}

	public static function proxies( mixed $raw ): string {
		$policy = ( new ProxyPolicy() )->read( $raw );
		$mode   = is_array( $policy ) ? ( $policy['mode'] ?? '' ) : '';
		return is_string( $mode ) && in_array( $mode, array( 'off', 'xff', 'single' ), true ) ? $mode : 'unknown';
	}

	public static function activity( mixed $raw ): string {
		if ( '1' === $raw || 1 === $raw || true === $raw ) {
			return 'on';
		}
		return null === $raw || false === $raw || '' === $raw || '0' === $raw || 0 === $raw ? 'off' : 'unknown';
	}

	public static function baselines( mixed $raw ): string {
		if ( null === $raw || false === $raw || '' === $raw ) {
			return 'none';
		}
		if ( ! is_string( $raw ) || strlen( $raw ) > 524288 ) {
			return 'unknown';
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.json_decode_json_decode -- Local baseline record only. No preview is created.
		$state = json_decode( $raw, true );
		if ( ! is_array( $state ) || 1 !== ( $state['version'] ?? null ) || ! is_array( $state['baselines'] ?? null ) ) {
			return 'unknown';
		}
		if ( count( $state['baselines'] ) > 0 ) {
			return 'stored';
		}
		$previews = $state['previews'] ?? null;
		return is_array( $previews ) && count( $previews ) > 0 ? 'preview' : 'none';
	}
}
