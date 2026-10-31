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
			'https-admin'            => __( 'Admin pages use HTTPS', 'amsec-security-scanner' ),
			'core-updates'           => __( 'Update settings', 'amsec-security-scanner' ),
			'default-admin-login'    => __( 'Administrator accounts', 'amsec-security-scanner' ),
			'debug-display'          => __( 'Errors shown to visitors', 'amsec-security-scanner' ),
			'file-editor'            => __( 'Built-in file editor', 'amsec-security-scanner' ),
			'login-rate-mode'        => __( 'Sign-in attempt limits', 'amsec-security-scanner' ),
			'filesystem-permissions' => __( 'Folder permissions', 'amsec-security-scanner' ),
			'file-modes'             => __( 'File modes on key files', 'amsec-security-scanner' ),
			'uploads-php-execution'  => __( 'PHP running in uploads', 'amsec-security-scanner' ),
			'pingbacks'              => __( 'Pingbacks', 'amsec-security-scanner' ),
			'xmlrpc-auth'            => __( 'XML-RPC sign-in', 'amsec-security-scanner' ),
			'authenticator-app'      => __( 'Authenticator app sign-in', 'amsec-security-scanner' ),
			'passkeys-status'        => __( 'Passkeys', 'amsec-security-scanner' ),
			'captcha-login'          => __( 'Login bot trap', 'amsec-security-scanner' ),
			'compromised-passwords'  => __( 'Breached password check', 'amsec-security-scanner' ),
			'login-hints'            => __( 'Sign-in error hints', 'amsec-security-scanner' ),
			'author-archives'        => __( 'Author archive pages', 'amsec-security-scanner' ),
			'rest-user-list'         => __( 'Public REST user list', 'amsec-security-scanner' ),
			'version-tag'            => __( 'WordPress version tag', 'amsec-security-scanner' ),
			'discovery-links'        => __( 'Discovery links in the page head', 'amsec-security-scanner' ),
			'readme-file'            => __( 'readme.html', 'amsec-security-scanner' ),
			'license-file'           => __( 'license.txt', 'amsec-security-scanner' ),
			'debug-log'              => __( 'debug.log', 'amsec-security-scanner' ),
			'sample-config'          => __( 'wp-config-sample.php', 'amsec-security-scanner' ),
			'error-log'              => __( 'error_log files', 'amsec-security-scanner' ),
			'config-backup'          => __( 'Backup copies of wp-config.php', 'amsec-security-scanner' ),
			'php-version'            => __( 'PHP version', 'amsec-security-scanner' ),
			'background-updates'     => __( 'Background updates', 'amsec-security-scanner' ),
			'plugin-updates'         => __( 'Plugin updates', 'amsec-security-scanner' ),
			'theme-updates'          => __( 'Theme updates', 'amsec-security-scanner' ),
			'inactive-plugins'       => __( 'Inactive plugins', 'amsec-security-scanner' ),
			'inactive-themes'        => __( 'Inactive themes', 'amsec-security-scanner' ),
			'uploads-php-files'      => __( 'PHP files in uploads', 'amsec-security-scanner' ),
			'root-exposure'          => __( 'Files exposed in the site root', 'amsec-security-scanner' ),
			'bot-controls'           => __( 'Bot protection mode', 'amsec-security-scanner' ),
			'rest-rates'             => __( 'REST rate limits', 'amsec-security-scanner' ),
			'rest-request-watch'     => __( 'REST request watch', 'amsec-security-scanner' ),
			'finding-emails'         => __( 'Finding emails', 'amsec-security-scanner' ),
			'weekly-digest'          => __( 'Weekly digest', 'amsec-security-scanner' ),
			'traffic-history'        => __( 'Traffic history', 'amsec-security-scanner' ),
			'network-controls'       => __( 'Network controls', 'amsec-security-scanner' ),
			'trusted-proxies'        => __( 'Trusted proxies', 'amsec-security-scanner' ),
			'security-activity'      => __( 'Security activity log', 'amsec-security-scanner' ),
			'account-sessions'       => __( 'Account sessions', 'amsec-security-scanner' ),
			'code-baselines'         => __( 'Code baselines', 'amsec-security-scanner' ),
			'daily-checks'           => __( 'Daily checks', 'amsec-security-scanner' ),
			'daily-file-checks'      => __( 'Daily file checks', 'amsec-security-scanner' ),
			'rule-review'            => __( 'Rule review', 'amsec-security-scanner' ),
			'ai-readers'             => __( 'AI crawler access', 'amsec-security-scanner' ),
			'ai-readiness'           => __( 'AI readiness', 'amsec-security-scanner' ),
			'known-holes'            => __( 'Known security holes', 'amsec-security-scanner' ),
			'release-files'          => __( 'Release file integrity', 'amsec-security-scanner' ),
			'closed-plugins'         => __( 'Closed plugins', 'amsec-security-scanner' ),
			'public-content'         => __( 'Public content', 'amsec-security-scanner' ),
			'local-code'             => __( 'Local plugin code', 'amsec-security-scanner' ),
			'suspicious-files'       => __( 'Suspicious files', 'amsec-security-scanner' ),
			'local-inventory'        => __( 'Local file inventory', 'amsec-security-scanner' ),
			'security-headers'       => __( 'Security headers follow-up', 'amsec-security-scanner' ),
		);
	}

	/** @return array<string, array{0: string, 1: list<string>}> Scan categories in run order. File passes run before the checks that read them, and the header request before its follow-up. */
	private static function groups(): array {
		return array(
			'code'     => array( __( 'Malware and code', 'amsec-security-scanner' ), array( 'file-code', 'file-inventory', 'file-content', 'local-code', 'suspicious-files', 'local-inventory', 'release-files', 'public-content' ) ),
			'files'    => array( __( 'Files and folders', 'amsec-security-scanner' ), array( 'filesystem-permissions', 'file-modes', 'uploads-php-execution', 'uploads-php-files', 'root-exposure', 'readme-file', 'license-file', 'debug-log', 'sample-config', 'error-log', 'config-backup' ) ),
			'sign-in'  => array( __( 'Sign-in and accounts', 'amsec-security-scanner' ), array( 'https-admin', 'default-admin-login', 'login-rate-mode', 'xmlrpc-auth', 'authenticator-app', 'passkeys-status', 'captcha-login', 'compromised-passwords', 'login-hints', 'account-sessions' ) ),
			'updates'  => array( __( 'Updates and versions', 'amsec-security-scanner' ), array( 'core-updates', 'php-version', 'background-updates', 'plugin-updates', 'theme-updates', 'inactive-plugins', 'inactive-themes', 'known-holes', 'closed-plugins' ) ),
			'settings' => array( __( 'Site settings', 'amsec-security-scanner' ), array( 'debug-display', 'file-editor', 'pingbacks', 'author-archives', 'rest-user-list', 'version-tag', 'discovery-links' ) ),
			'traffic'  => array( __( 'Bots and traffic', 'amsec-security-scanner' ), array( 'bot-controls', 'rest-rates', 'rest-request-watch', 'network-controls', 'trusted-proxies', 'traffic-history', 'header-request', 'security-headers' ) ),
			'watch'    => array( __( 'Monitoring and alerts', 'amsec-security-scanner' ), array( 'finding-emails', 'weekly-digest', 'security-activity', 'code-baselines', 'daily-checks', 'daily-file-checks', 'rule-review' ) ),
			'ai'       => array( __( 'AI', 'amsec-security-scanner' ), array( 'ai-readers', 'ai-readiness' ) ),
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
			$plan[] = array( __( 'Other', 'amsec-security-scanner' ), $other );
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
				'file-code'      => __( 'Malware scan: next batch of files', 'amsec-security-scanner' ),
				'file-inventory' => __( 'Listing files in the site folders', 'amsec-security-scanner' ),
				'file-content'   => __( 'Posts and comments: checking links', 'amsec-security-scanner' ),
				'header-request' => __( 'Homepage response headers', 'amsec-security-scanner' ),
				'save'           => __( 'Saving the results', 'amsec-security-scanner' ),
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
				$note = sprintf( _n( '%s file checked so far', '%s files checked so far', $cursor->processed, 'amsec-security-scanner' ), number_format_i18n( $cursor->processed ) );
			}
		} elseif ( 'header-request' === $id ) {
			try {
				$headers = ( new WordPressHeaderService() )->create();
				$headers->check( $headers->fingerprint(), time() );
			} catch ( Throwable ) {
				$note = __( 'The homepage could not be read', 'amsec-security-scanner' );
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
