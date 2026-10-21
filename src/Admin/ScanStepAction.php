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
			'https-admin'            => __( 'Admin pages use HTTPS', 'amazing-security' ),
			'core-updates'           => __( 'Update settings', 'amazing-security' ),
			'default-admin-login'    => __( 'Administrator accounts', 'amazing-security' ),
			'debug-display'          => __( 'Errors shown to visitors', 'amazing-security' ),
			'file-editor'            => __( 'Built-in file editor', 'amazing-security' ),
			'login-rate-mode'        => __( 'Sign-in attempt limits', 'amazing-security' ),
			'filesystem-permissions' => __( 'Folder permissions', 'amazing-security' ),
			'file-modes'             => __( 'File modes on key files', 'amazing-security' ),
			'uploads-php-execution'  => __( 'PHP running in uploads', 'amazing-security' ),
			'pingbacks'              => __( 'Pingbacks', 'amazing-security' ),
			'xmlrpc-auth'            => __( 'XML-RPC sign-in', 'amazing-security' ),
			'authenticator-app'      => __( 'Authenticator app sign-in', 'amazing-security' ),
			'passkeys-status'        => __( 'Passkeys', 'amazing-security' ),
			'captcha-login'          => __( 'Login bot trap', 'amazing-security' ),
			'compromised-passwords'  => __( 'Breached password check', 'amazing-security' ),
			'login-hints'            => __( 'Sign-in error hints', 'amazing-security' ),
			'author-archives'        => __( 'Author archive pages', 'amazing-security' ),
			'rest-user-list'         => __( 'Public REST user list', 'amazing-security' ),
			'version-tag'            => __( 'WordPress version tag', 'amazing-security' ),
			'discovery-links'        => __( 'Discovery links in the page head', 'amazing-security' ),
			'readme-file'            => __( 'readme.html', 'amazing-security' ),
			'license-file'           => __( 'license.txt', 'amazing-security' ),
			'debug-log'              => __( 'debug.log', 'amazing-security' ),
			'sample-config'          => __( 'wp-config-sample.php', 'amazing-security' ),
			'error-log'              => __( 'error_log files', 'amazing-security' ),
			'config-backup'          => __( 'Backup copies of wp-config.php', 'amazing-security' ),
			'php-version'            => __( 'PHP version', 'amazing-security' ),
			'background-updates'     => __( 'Background updates', 'amazing-security' ),
			'plugin-updates'         => __( 'Plugin updates', 'amazing-security' ),
			'theme-updates'          => __( 'Theme updates', 'amazing-security' ),
			'inactive-plugins'       => __( 'Inactive plugins', 'amazing-security' ),
			'inactive-themes'        => __( 'Inactive themes', 'amazing-security' ),
			'uploads-php-files'      => __( 'PHP files in uploads', 'amazing-security' ),
			'root-exposure'          => __( 'Files exposed in the site root', 'amazing-security' ),
			'bot-controls'           => __( 'Bot protection mode', 'amazing-security' ),
			'rest-rates'             => __( 'REST rate limits', 'amazing-security' ),
			'rest-request-watch'     => __( 'REST request watch', 'amazing-security' ),
			'finding-emails'         => __( 'Finding emails', 'amazing-security' ),
			'weekly-digest'          => __( 'Weekly digest', 'amazing-security' ),
			'traffic-history'        => __( 'Traffic history', 'amazing-security' ),
			'network-controls'       => __( 'Network controls', 'amazing-security' ),
			'trusted-proxies'        => __( 'Trusted proxies', 'amazing-security' ),
			'security-activity'      => __( 'Security activity log', 'amazing-security' ),
			'account-sessions'       => __( 'Account sessions', 'amazing-security' ),
			'code-baselines'         => __( 'Code baselines', 'amazing-security' ),
			'daily-checks'           => __( 'Daily checks', 'amazing-security' ),
			'daily-file-checks'      => __( 'Daily file checks', 'amazing-security' ),
			'rule-review'            => __( 'Rule review', 'amazing-security' ),
			'ai-readers'             => __( 'AI crawler access', 'amazing-security' ),
			'ai-readiness'           => __( 'AI readiness', 'amazing-security' ),
			'known-holes'            => __( 'Known security holes', 'amazing-security' ),
			'release-files'          => __( 'Release file integrity', 'amazing-security' ),
			'closed-plugins'         => __( 'Closed plugins', 'amazing-security' ),
			'public-content'         => __( 'Public content', 'amazing-security' ),
			'local-code'             => __( 'Local plugin code', 'amazing-security' ),
			'suspicious-files'       => __( 'Suspicious files', 'amazing-security' ),
			'local-inventory'        => __( 'Local file inventory', 'amazing-security' ),
			'security-headers'       => __( 'Security headers follow-up', 'amazing-security' ),
		);
	}

	/** @return list<string> Step ids in order: the file pass, every check, the optional header request, then save. */
	public static function steps(): array {
		$steps = array( 'file-pass' );
		foreach ( LocalHardeningScanService::all() as $check ) {
			if ( 'security-headers' === $check->id() && ScanOptions::headers() ) {
				$steps[] = 'header-request';
			}
			$steps[] = $check->id();
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
				'file-pass'      => __( 'Moving the file scan forward', 'amazing-security' ),
				'header-request' => __( 'Homepage response headers', 'amazing-security' ),
				'save'           => __( 'Saving the results', 'amazing-security' ),
			);
			wp_send_json_success(
				array(
					'token' => $token,
					'steps' => array_map( static fn( string $id ): string => $labels[ $id ] ?? $id, $steps ),
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
		if ( 'file-pass' === $id ) {
			( new LocalPass() )->advance();
			$cursor = LocalCodeScan::cursor();
			if ( null !== $cursor ) {
				/* translators: %s: number of files. */
				$note = sprintf( _n( '%s file checked so far', '%s files checked so far', $cursor->processed, 'amazing-security' ), number_format_i18n( $cursor->processed ) );
			}
		} elseif ( 'header-request' === $id ) {
			try {
				$headers = ( new WordPressHeaderService() )->create();
				$headers->check( $headers->fingerprint(), time() );
			} catch ( Throwable ) {
				$note = __( 'The homepage could not be read', 'amazing-security' );
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
