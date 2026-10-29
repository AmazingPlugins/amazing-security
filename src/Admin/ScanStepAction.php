<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Findings\CheckResult;
use AmazingPlugins\Security\Findings\FindingsRepository;
use AmazingPlugins\Security\Headers\WordPressHeaderService;
use AmazingPlugins\Security\Scan\LocalCodeScan;
use AmazingPlugins\Security\Scan\LocalHardeningScanService;
use AmazingPlugins\Security\Scan\LocalPass;
use AmazingPlugins\Security\Scan\ScanContext;
use AmazingPlugins\Security\Scan\ScanCoordinator;
use AmazingPlugins\Security\Scan\ScanRun;
use DateTimeImmutable;
use DateTimeZone;
use Throwable;

/**
 * Runs the Scan button one step per request, so each progress row ticks only when its check has really finished.
 * Without JavaScript the form still posts to ScanAction, which runs the same checks in one go.
 */
final class ScanStepAction {
	private const SESSION = 'amsec_scan_session_';

	/** @return array<string, string> */
	public static function labels(): array {
		return array(
			'https-admin'            => __( 'Admin pages use HTTPS', 'amazingplugins-security-scanner' ),
			'core-updates'           => __( 'Update settings', 'amazingplugins-security-scanner' ),
			'default-admin-login'    => __( 'Administrator accounts', 'amazingplugins-security-scanner' ),
			'debug-display'          => __( 'Errors shown to visitors', 'amazingplugins-security-scanner' ),
			'file-editor'            => __( 'Built-in file editor', 'amazingplugins-security-scanner' ),
			'login-rate-mode'        => __( 'Sign-in attempt limits', 'amazingplugins-security-scanner' ),
			'filesystem-permissions' => __( 'Folder permissions', 'amazingplugins-security-scanner' ),
			'file-modes'             => __( 'File modes on key files', 'amazingplugins-security-scanner' ),
			'uploads-php-execution'  => __( 'PHP running in uploads', 'amazingplugins-security-scanner' ),
			'pingbacks'              => __( 'Pingbacks', 'amazingplugins-security-scanner' ),
			'xmlrpc-auth'            => __( 'XML-RPC sign-in', 'amazingplugins-security-scanner' ),
			'authenticator-app'      => __( 'Authenticator app sign-in', 'amazingplugins-security-scanner' ),
			'passkeys-status'        => __( 'Passkeys', 'amazingplugins-security-scanner' ),
			'captcha-login'          => __( 'Login bot trap', 'amazingplugins-security-scanner' ),
			'compromised-passwords'  => __( 'Breached password check', 'amazingplugins-security-scanner' ),
			'login-hints'            => __( 'Sign-in error hints', 'amazingplugins-security-scanner' ),
			'author-archives'        => __( 'Author archive pages', 'amazingplugins-security-scanner' ),
			'rest-user-list'         => __( 'Public REST user list', 'amazingplugins-security-scanner' ),
			'version-tag'            => __( 'WordPress version tag', 'amazingplugins-security-scanner' ),
			'discovery-links'        => __( 'Discovery links in the page head', 'amazingplugins-security-scanner' ),
			'readme-file'            => __( 'readme.html', 'amazingplugins-security-scanner' ),
			'license-file'           => __( 'license.txt', 'amazingplugins-security-scanner' ),
			'debug-log'              => __( 'debug.log', 'amazingplugins-security-scanner' ),
			'sample-config'          => __( 'wp-config-sample.php', 'amazingplugins-security-scanner' ),
			'error-log'              => __( 'error_log files', 'amazingplugins-security-scanner' ),
			'config-backup'          => __( 'Backup copies of wp-config.php', 'amazingplugins-security-scanner' ),
			'php-version'            => __( 'PHP version', 'amazingplugins-security-scanner' ),
			'background-updates'     => __( 'Background updates', 'amazingplugins-security-scanner' ),
			'plugin-updates'         => __( 'Plugin updates', 'amazingplugins-security-scanner' ),
			'theme-updates'          => __( 'Theme updates', 'amazingplugins-security-scanner' ),
			'inactive-plugins'       => __( 'Inactive plugins', 'amazingplugins-security-scanner' ),
			'inactive-themes'        => __( 'Inactive themes', 'amazingplugins-security-scanner' ),
			'uploads-php-files'      => __( 'PHP files in uploads', 'amazingplugins-security-scanner' ),
			'root-exposure'          => __( 'Files exposed in the site root', 'amazingplugins-security-scanner' ),
			'bot-controls'           => __( 'Bot protection mode', 'amazingplugins-security-scanner' ),
			'rest-rates'             => __( 'REST rate limits', 'amazingplugins-security-scanner' ),
			'rest-request-watch'     => __( 'REST request watch', 'amazingplugins-security-scanner' ),
			'finding-emails'         => __( 'Finding emails', 'amazingplugins-security-scanner' ),
			'weekly-digest'          => __( 'Weekly digest', 'amazingplugins-security-scanner' ),
			'traffic-history'        => __( 'Traffic history', 'amazingplugins-security-scanner' ),
			'network-controls'       => __( 'Network controls', 'amazingplugins-security-scanner' ),
			'trusted-proxies'        => __( 'Trusted proxies', 'amazingplugins-security-scanner' ),
			'security-activity'      => __( 'Security activity log', 'amazingplugins-security-scanner' ),
			'account-sessions'       => __( 'Account sessions', 'amazingplugins-security-scanner' ),
			'code-baselines'         => __( 'Code baselines', 'amazingplugins-security-scanner' ),
			'daily-checks'           => __( 'Daily checks', 'amazingplugins-security-scanner' ),
			'daily-file-checks'      => __( 'Daily file checks', 'amazingplugins-security-scanner' ),
			'rule-review'            => __( 'Rule review', 'amazingplugins-security-scanner' ),
			'ai-readers'             => __( 'AI crawler access', 'amazingplugins-security-scanner' ),
			'ai-readiness'           => __( 'AI readiness', 'amazingplugins-security-scanner' ),
			'known-holes'            => __( 'Known security holes', 'amazingplugins-security-scanner' ),
			'release-files'          => __( 'Release file integrity', 'amazingplugins-security-scanner' ),
			'closed-plugins'         => __( 'Closed plugins', 'amazingplugins-security-scanner' ),
			'public-content'         => __( 'Public content', 'amazingplugins-security-scanner' ),
			'local-code'             => __( 'Local plugin code', 'amazingplugins-security-scanner' ),
			'suspicious-files'       => __( 'Suspicious files', 'amazingplugins-security-scanner' ),
			'local-inventory'        => __( 'Local file inventory', 'amazingplugins-security-scanner' ),
			'security-headers'       => __( 'Security headers follow-up', 'amazingplugins-security-scanner' ),
		);
	}

	/** @return array<string, array{0: string, 1: list<string>}> Scan categories in run order. File passes run before the checks that read them, and the header request before its follow-up. */
	private static function groups(): array {
		return array(
			'code'     => array( __( 'Malware and code', 'amazingplugins-security-scanner' ), array( 'file-code', 'file-inventory', 'file-content', 'local-code', 'suspicious-files', 'local-inventory', 'release-files', 'public-content' ) ),
			'files'    => array( __( 'Files and folders', 'amazingplugins-security-scanner' ), array( 'filesystem-permissions', 'file-modes', 'uploads-php-execution', 'uploads-php-files', 'root-exposure', 'readme-file', 'license-file', 'debug-log', 'sample-config', 'error-log', 'config-backup' ) ),
			'sign-in'  => array( __( 'Sign-in and accounts', 'amazingplugins-security-scanner' ), array( 'https-admin', 'default-admin-login', 'login-rate-mode', 'xmlrpc-auth', 'authenticator-app', 'passkeys-status', 'captcha-login', 'compromised-passwords', 'login-hints', 'account-sessions' ) ),
			'updates'  => array( __( 'Updates and versions', 'amazingplugins-security-scanner' ), array( 'core-updates', 'php-version', 'background-updates', 'plugin-updates', 'theme-updates', 'inactive-plugins', 'inactive-themes', 'known-holes', 'closed-plugins' ) ),
			'settings' => array( __( 'Site settings', 'amazingplugins-security-scanner' ), array( 'debug-display', 'file-editor', 'pingbacks', 'author-archives', 'rest-user-list', 'version-tag', 'discovery-links' ) ),
			'traffic'  => array( __( 'Bots and traffic', 'amazingplugins-security-scanner' ), array( 'bot-controls', 'rest-rates', 'rest-request-watch', 'network-controls', 'trusted-proxies', 'traffic-history', 'header-request', 'security-headers' ) ),
			'watch'    => array( __( 'Monitoring and alerts', 'amazingplugins-security-scanner' ), array( 'finding-emails', 'weekly-digest', 'security-activity', 'code-baselines', 'daily-checks', 'daily-file-checks', 'rule-review' ) ),
			'ai'       => array( __( 'AI', 'amazingplugins-security-scanner' ), array( 'ai-readers', 'ai-readiness' ) ),
		);
	}

	/**
	 * Categories with the step ids that will really run, in order. A check missing from every category still runs, under "Other".
	 *
	 * @return list<array{0: string, 1: list<string>}>
	 */
	public static function plan(): array {
		$checks = array();
		foreach ( LocalHardeningScanService::all() as $check ) {
			$checks[ $check->id() ] = true;
		}
		$extra  = array( 'file-code', 'file-inventory', 'file-content' );
		$extra  = array_merge( $extra, ScanOptions::headers() ? array( 'header-request' ) : array() );
		$plan   = array();
		$placed = array();
		foreach ( self::groups() as $group ) {
			$ids = array_values( array_filter( $group[1], static fn( string $id ): bool => isset( $checks[ $id ] ) || in_array( $id, $extra, true ) ) );
			if ( array() !== $ids ) {
				$plan[] = array( $group[0], $ids );
				$placed = array_merge( $placed, $ids );
			}
		}
		$other = array_values( array_diff( array_keys( $checks ), $placed ) );
		if ( array() !== $other ) {
			$plan[] = array( __( 'Other', 'amazingplugins-security-scanner' ), $other );
		}
		return $plan;
	}

	/** @return list<string> Every step id in run order, ending with save. */
	public static function steps(): array {
		$steps = array();
		foreach ( self::plan() as $group ) {
			array_push( $steps, ...$group[1] );
		}
		$steps[] = 'save';
		return $steps;
	}

	public function handle(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( null, 403 );
		}
		check_ajax_referer( 'amazing_security_scan' );
		$key = self::SESSION . get_current_user_id();
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce checked above.
		$step = isset( $_POST['step'] ) ? sanitize_key( wp_unslash( $_POST['step'] ) ) : '';
		if ( 'start' === $step ) {
			$token = bin2hex( random_bytes( 10 ) );
			$steps = self::steps();
			set_transient(
				$key,
				array(
					'token'   => $token,
					'steps'   => $steps,
					'next'    => 0,
					'started' => time(),
					'results' => array(),
					'partial' => false,
				),
				15 * MINUTE_IN_SECONDS
			);
			$labels = self::labels() + array(
				'file-code'      => __( 'Malware scan: next batch of files', 'amazingplugins-security-scanner' ),
				'file-inventory' => __( 'Listing files in the site folders', 'amazingplugins-security-scanner' ),
				'file-content'   => __( 'Posts and comments: checking links', 'amazingplugins-security-scanner' ),
				'header-request' => __( 'Homepage response headers', 'amazingplugins-security-scanner' ),
				'save'           => __( 'Saving the results', 'amazingplugins-security-scanner' ),
			);
			$groups = array();
			foreach ( self::plan() as $group ) {
				$groups[] = array(
					'name'  => $group[0],
					'steps' => array_map( static fn( string $id ): string => $labels[ $id ] ?? $id, $group[1] ),
				);
			}
			wp_send_json_success(
				array(
					'token'  => $token,
					'groups' => $groups,
					'save'   => $labels['save'],
				)
			);
		}
		$session = get_transient( $key );
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce checked above.
		$token = isset( $_POST['token'] ) ? sanitize_key( wp_unslash( $_POST['token'] ) ) : '';
		// Steps run strictly in order; a second tab or a replayed request gets a clean error instead of mixing scans.
		if ( ! is_array( $session ) || ! hash_equals( (string) $session['token'], $token ) || (string) $session['next'] !== $step ) {
			wp_send_json_error( null, 409 );
		}
		$id   = $session['steps'][ (int) $step ] ?? '';
		$note = '';
		if ( 'file-inventory' === $id ) {
			( new LocalPass() )->inventory();
		} elseif ( 'file-content' === $id ) {
			( new LocalPass() )->content();
		} elseif ( 'file-code' === $id ) {
			// A short batch keeps the progress moving; the background tick reads the remaining files.
			( new LocalPass() )->code( 1.5 );
			$cursor = LocalCodeScan::cursor();
			if ( null !== $cursor ) {
				/* translators: %s: number of files. */
				$note = sprintf( _n( '%s file checked so far', '%s files checked so far', $cursor->processed, 'amazingplugins-security-scanner' ), number_format_i18n( $cursor->processed ) );
			}
		} elseif ( 'header-request' === $id ) {
			try {
				$headers = ( new WordPressHeaderService() )->create();
				$headers->check( $headers->fingerprint(), time() );
			} catch ( Throwable ) {
				$note = __( 'The homepage could not be read', 'amazingplugins-security-scanner' );
			}
		} elseif ( 'save' === $id ) {
			delete_transient( $key );
			$run = new ScanRun(
				( new DateTimeImmutable( 'now', new DateTimeZone( 'UTC' ) ) )->setTimestamp( (int) $session['started'] ),
				new DateTimeImmutable( 'now', new DateTimeZone( 'UTC' ) ),
				array_map( array( CheckResult::class, 'fromArray' ), $session['results'] ),
				(bool) $session['partial']
			);
			try {
				( new FindingsRepository() )->save( $run );
			} catch ( Throwable ) {
				wp_send_json_error( null, 500 );
			}
			wp_send_json_success( array( 'done' => admin_url( 'admin.php?page=amazing-security' ) ) );
		} else {
			$check = null;
			foreach ( LocalHardeningScanService::all() as $candidate ) {
				if ( $candidate->id() === $id ) {
					$check = $candidate;
				}
			}
			if ( null === $check ) {
				wp_send_json_error( null, 400 );
			}
			// The coordinator turns a failing check into an "unknown" row, the same as a full scan.
			$run                = ( new ScanCoordinator() )->run( array( $check ), new ScanContext() );
			$session['partial'] = $session['partial'] || $run->partial;
			$session['results'] = array_merge( $session['results'], array_map( static fn( CheckResult $result ): array => $result->toArray(), $run->results ) );
		}
		$session['next'] = (int) $step + 1;
		set_transient( $key, $session, 15 * MINUTE_IN_SECONDS );
		wp_send_json_success( array( 'note' => $note ) );
	}
}
