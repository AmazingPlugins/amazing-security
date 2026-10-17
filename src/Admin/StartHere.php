<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Findings\CheckResult;
use AmazingPlugins\Security\Findings\State;

/** Fixed first suggestions from a completed local scan. */
final class StartHere {
	public const ORDER = array( 'https-admin', 'core-updates', 'default-admin-login', 'debug-display', 'file-editor', 'login-rate-mode' );
	public const LATER = array( 'uploads-php-execution', 'uploads-php-files', 'file-modes', 'pingbacks', 'xmlrpc-auth', 'captcha-login', 'compromised-passwords', 'login-hints', 'author-archives', 'rest-user-list', 'version-tag', 'discovery-links', 'readme-file', 'license-file', 'debug-log', 'sample-config', 'error-log', 'config-backup', 'php-version', 'background-updates', 'plugin-updates', 'theme-updates', 'inactive-plugins', 'inactive-themes', 'root-exposure', 'bot-controls', 'rest-rates', 'rest-request-watch', 'finding-emails', 'weekly-digest', 'traffic-history', 'network-controls', 'trusted-proxies', 'security-activity', 'account-sessions', 'code-baselines', 'daily-checks', 'daily-file-checks', 'rule-review', 'ai-readers', 'ai-readiness', 'known-holes', 'release-files', 'closed-plugins', 'public-content', 'local-code', 'suspicious-files', 'local-inventory', 'security-headers' );

	public static function label( string $checkId ): string {
		return match ( $checkId ) {
			'https-admin' => __( 'HTTPS', 'amazing-security' ),
			'core-updates' => __( 'WordPress updates', 'amazing-security' ),
			'default-admin-login' => __( 'Admin login', 'amazing-security' ),
			'debug-display' => __( 'Debug display', 'amazing-security' ),
			'file-editor' => __( 'Theme and plugin editor', 'amazing-security' ),
			'login-rate-mode' => __( 'Login monitoring', 'amazing-security' ),
			'uploads-php-execution' => __( 'PHP in uploads', 'amazing-security' ),
			'uploads-php-files' => __( 'PHP files in uploads', 'amazing-security' ),
			'file-modes' => __( 'File modes', 'amazing-security' ),
			'filesystem-permissions' => __( 'File permissions', 'amazing-security' ),
			'pingbacks' => __( 'Pingbacks', 'amazing-security' ),
			'xmlrpc-auth' => __( 'XML-RPC sign-in', 'amazing-security' ),
			'captcha-login' => __( 'Login CAPTCHA', 'amazing-security' ),
			'compromised-passwords' => __( 'Compromised passwords', 'amazing-security' ),
			'login-hints' => __( 'Login messages', 'amazing-security' ),
			'author-archives' => __( 'Author pages', 'amazing-security' ),
			'rest-user-list' => __( 'REST user list', 'amazing-security' ),
			'version-tag' => __( 'Version tag', 'amazing-security' ),
			'discovery-links' => __( 'Discovery links', 'amazing-security' ),
			'readme-file' => __( 'Readme file', 'amazing-security' ),
			'license-file' => __( 'License file', 'amazing-security' ),
			'debug-log' => __( 'Debug log', 'amazing-security' ),
			'sample-config' => __( 'Sample config', 'amazing-security' ),
			'error-log' => __( 'Error log', 'amazing-security' ),
			'config-backup' => __( 'Config backup', 'amazing-security' ),
			'php-version' => __( 'PHP version', 'amazing-security' ),
			'background-updates' => __( 'Background updates', 'amazing-security' ),
			'plugin-updates' => __( 'Plugin updates', 'amazing-security' ),
			'theme-updates' => __( 'Theme updates', 'amazing-security' ),
			'inactive-plugins' => __( 'Inactive plugins', 'amazing-security' ),
			'inactive-themes' => __( 'Inactive themes', 'amazing-security' ),
			'root-exposure' => __( 'Root files', 'amazing-security' ),
			'bot-controls' => __( 'Bot controls', 'amazing-security' ),
			'rest-rates' => __( 'REST limits', 'amazing-security' ),
			'rest-request-watch' => __( 'REST request watch', 'amazing-security' ),
			'finding-emails' => __( 'Finding emails', 'amazing-security' ),
			'weekly-digest' => __( 'Weekly digest', 'amazing-security' ),
			'traffic-history' => __( 'Traffic history', 'amazing-security' ),
			'network-controls' => __( 'Network controls', 'amazing-security' ),
			'trusted-proxies' => __( 'Trusted proxies', 'amazing-security' ),
			'security-activity' => __( 'Security activity', 'amazing-security' ),
			'account-sessions' => __( 'Account sessions', 'amazing-security' ),
			'code-baselines' => __( 'Code baselines', 'amazing-security' ),
			'daily-checks' => __( 'Daily checks', 'amazing-security' ),
			'daily-file-checks' => __( 'Daily file checks', 'amazing-security' ),
			'rule-review' => __( 'Rule review', 'amazing-security' ),
			'ai-readers' => __( 'Bots and AI readers', 'amazing-security' ),
			'ai-readiness' => __( 'AI security and readiness', 'amazing-security' ),
			'known-holes' => __( 'Known holes', 'amazing-security' ),
			'release-files' => __( 'Release files', 'amazing-security' ),
			'closed-plugins' => __( 'Closed plugins', 'amazing-security' ),
			'public-content' => __( 'Posts and comments', 'amazing-security' ),
			'local-code' => __( 'Local code scan', 'amazing-security' ),
			'suspicious-files' => __( 'Suspicious files', 'amazing-security' ),
			'local-inventory' => __( 'Local inventory', 'amazing-security' ),
			'security-headers' => __( 'Security headers', 'amazing-security' ),
			default => $checkId,
		};
	}

	/** @param array<int, mixed> $results */
	public static function rows( array $results, array $ids ): array {
		$found = array();
		foreach ( $results as $result ) {
			if ( $result instanceof CheckResult && ! isset( $found[ $result->checkId ] ) ) {
				$found[ $result->checkId ] = $result;
			}
		}
		$rows = array();
		foreach ( $ids as $id ) {
			if ( isset( $found[ $id ] ) ) {
				$rows[] = $found[ $id ];
			}
		}
		return $rows;
	}

	/** @return array<string, string>|null */
	public static function control( CheckResult $result ): ?array {
		$stored  = is_string( $result->evidence['stored'] ?? null ) ? $result->evidence['stored'] : '';
		$enabled = is_string( $result->evidence['enabled'] ?? null ) ? $result->evidence['enabled'] : '';
		return match ( $result->checkId ) {
			'inactive-plugins' => State::WARN === $result->state ? array(
				'label'  => __( 'Review plugins', 'amazing-security' ),
				'screen' => 'plugins.php',
			) : null,
			'inactive-themes' => State::WARN === $result->state ? array(
				'label'  => __( 'Review themes', 'amazing-security' ),
				'screen' => 'themes.php',
			) : null,
			'https-admin' => State::PASS === $result->state ? null : array(
				'label'  => __( 'Open Site Health', 'amazing-security' ),
				'screen' => 'site-health.php',
			),
			'core-updates', 'plugin-updates', 'theme-updates' => in_array( $result->state, array( State::WARN, State::UNKNOWN ), true ) ? array(
				'label'  => __( 'Review updates', 'amazing-security' ),
				'screen' => 'update-core.php',
			) : null,
			'default-admin-login' => State::WARN === $result->state ? array(
				'label'  => __( 'Review administrators', 'amazing-security' ),
				'screen' => 'users.php',
			) : null,
			'login-rate-mode' => State::PASS === $result->state ? null : array(
				'label' => __( 'Open login protection', 'amazing-security' ),
				'page'  => 'amsec-accounts',
				'hash'  => 'sign-in',
			),
			'authenticator-app' => State::PASS === $result->state ? null : array(
				'label' => __( 'Open authenticator status', 'amazing-security' ),
				'page'  => 'amsec-accounts',
				'hash'  => 'verification',
			),
			'passkeys-status' => State::PASS === $result->state ? null : array(
				'label' => __( 'Open passkey status', 'amazing-security' ),
				'page'  => 'amsec-accounts',
				'hash'  => 'passkeys',
			),
			'pingbacks' => 'open' === ( $result->evidence['status'] ?? '' ) ? array(
				'label'     => __( 'Turn off pingbacks', 'amazing-security' ),
				'action'    => 'amsec_approved_setting',
				'nonce'     => 'amsec_approved_setting',
				'operation' => 'close-pingbacks',
			) : null,
			'debug-display' => match ( $result->evidence['fix'] ?? '' ) {
				'plugin' => State::WARN === $result->state ? array(
					'label'     => __( 'Hide error details', 'amazing-security' ),
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'hide-debug-display',
				) : null,
				'plugin-on' => array(
					'label'     => __( 'Use the wp-config.php display again', 'amazing-security' ),
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'restore-debug-display',
				),
				default => State::PASS === $result->state ? null : array(
					'label'  => __( 'Open Site Health', 'amazing-security' ),
					'screen' => 'site-health.php',
				),
			},
			'file-editor' => match ( $result->evidence['fix'] ?? '' ) {
				'plugin' => State::WARN === $result->state ? array(
					'label'     => __( 'Turn off the file editor', 'amazing-security' ),
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'disable-file-editor',
				) : null,
				'plugin-on' => array(
					'label'     => __( 'Allow the file editor again', 'amazing-security' ),
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'restore-file-editor',
				),
				default => State::PASS === $result->state ? null : array(
					'label' => __( 'Review the file editor', 'amazing-security' ),
					'page'  => 'amsec-recovery',
				),
			},
			'captcha-login' => match ( $result->evidence['status'] ?? '' ) {
				'off' => array(
					'label'     => __( 'Turn on sign-in confirmation', 'amazing-security' ),
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'enable-login-confirm',
				),
				'on' => array(
					'label'     => __( 'Turn off sign-in confirmation', 'amazing-security' ),
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'disable-login-confirm',
				),
				default => null,
			},
			'compromised-passwords' => match ( $result->evidence['status'] ?? '' ) {
				'off' => array(
					'label'     => __( 'Turn on the local password list', 'amazing-security' ),
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'enable-common-passwords',
				),
				'on' => array(
					'label'     => __( 'Turn off the local password list', 'amazing-security' ),
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'disable-common-passwords',
				),
				default => null,
			},
			'login-hints' => match ( $result->evidence['status'] ?? '' ) {
				'off' => array(
					'label'     => __( 'Use one login message', 'amazing-security' ),
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'enable-login-hints',
				),
				'on' => array(
					'label'     => __( 'Show separate login messages', 'amazing-security' ),
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'disable-login-hints',
				),
				default => null,
			},
			'author-archives' => match ( $result->evidence['status'] ?? '' ) {
				'off' => array(
					'label'     => __( 'Hide author pages', 'amazing-security' ),
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'enable-author-archives',
				),
				'on' => array(
					'label'     => __( 'Show author pages', 'amazing-security' ),
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'disable-author-archives',
				),
				default => null,
			},
			'rest-user-list' => match ( $result->evidence['status'] ?? '' ) {
				'off' => array(
					'label'     => __( 'Require login for the user list', 'amazing-security' ),
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'enable-rest-users',
				),
				'on' => array(
					'label'     => __( 'Allow the public user list', 'amazing-security' ),
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'disable-rest-users',
				),
				default => null,
			},
			'version-tag' => match ( $result->evidence['status'] ?? '' ) {
				'off' => array(
					'label'     => __( 'Hide the version tag', 'amazing-security' ),
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'enable-version-tag',
				),
				'on' => array(
					'label'     => __( 'Show the version tag', 'amazing-security' ),
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'disable-version-tag',
				),
				default => null,
			},
			'discovery-links' => match ( $result->evidence['status'] ?? '' ) {
				'off' => array(
					'label'     => __( 'Remove discovery links', 'amazing-security' ),
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'enable-discovery-links',
				),
				'on' => array(
					'label'     => __( 'Show discovery links', 'amazing-security' ),
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'disable-discovery-links',
				),
				default => null,
			},
			'xmlrpc-auth' => 'open' === ( $result->evidence['auth'] ?? '' ) || State::PASS !== $result->state ? array(
				'label' => __( 'Open login protection', 'amazing-security' ),
				'page'  => 'amsec-accounts',
				'hash'  => 'sign-in',
			) : null,
			'uploads-php-execution' => array(
				'label' => __( 'Review PHP in uploads', 'amazing-security' ),
				'page'  => 'amsec-uploads',
			),
			'uploads-php-files' => State::PASS === $result->state ? null : array(
				'label'  => __( 'Review uploads', 'amazing-security' ),
				'screen' => 'upload.php',
			),
			'readme-file', 'license-file', 'debug-log', 'sample-config', 'error-log', 'config-backup', 'root-exposure', 'filesystem-permissions' => State::PASS === $result->state ? null : array(
				'label' => __( 'Review this finding', 'amazing-security' ),
				'page'  => 'amsec-exposure',
			),
			'php-version' => State::PASS === $result->state ? null : array(
				'label'  => __( 'Open Site Health', 'amazing-security' ),
				'screen' => 'site-health.php',
			),
			'background-updates' => State::PASS === $result->state ? null : array(
				'label'  => __( 'Review updates', 'amazing-security' ),
				'screen' => 'update-core.php',
			),
			'daily-checks', 'daily-file-checks' => State::PASS === $result->state ? null : array(
				'label' => __( 'Review the schedule', 'amazing-security' ),
				'page'  => 'amsec-schedule',
				'hash'  => 'amsec-schedule',
			),
			'local-code' => State::PASS === $result->state ? null : array(
				'label' => __( 'Review the file scan', 'amazing-security' ),
				'page'  => 'amsec-file-checks',
				'hash'  => 'amsec-file-scan',
			),
			'file-modes' => in_array( $result->state, array( State::WARN, State::UNKNOWN ), true ) ? array(
				'label' => __( 'Review file modes', 'amazing-security' ),
				'page'  => 'amsec-recovery',
			) : null,
			'bot-controls' => in_array( $result->evidence['mode'] ?? '', array( 'off', 'observe' ), true ) ? array(
				'label' => __( 'Review bot controls', 'amazing-security' ),
				'page'  => 'amsec-bots',
			) : null,
			'rest-rates' => in_array( $result->evidence['mode'] ?? '', array( 'off', 'observe' ), true ) ? array(
				'label' => __( 'Review REST limits', 'amazing-security' ),
				'page'  => 'amsec-rest-rates',
			) : null,
			'rest-request-watch' => 'disabled' === ( $result->evidence['status'] ?? '' ) ? array(
				'label' => __( 'Open Traffic', 'amazing-security' ),
				'page'  => 'amsec-traffic',
			) : null,
			'finding-emails' => 'off' === ( $result->evidence['status'] ?? '' ) ? array(
				'label' => __( 'Open notification settings', 'amazing-security' ),
				'page'  => 'amsec-settings',
				'hash'  => 'amsec-alerts',
			) : null,
			'weekly-digest' => 'off' === ( $result->evidence['status'] ?? '' ) ? array(
				'label' => __( 'Review weekly digest', 'amazing-security' ),
				'page'  => 'amsec-digest',
			) : null,
			'traffic-history' => 'off' === ( $result->evidence['status'] ?? '' ) ? array(
				'label' => __( 'Review traffic history', 'amazing-security' ),
				'page'  => 'amsec-traffic',
			) : null,
			'network-controls' => in_array( $result->evidence['status'] ?? '', array( 'observe', 'block' ), true ) ? array(
				'label' => __( 'Review network controls', 'amazing-security' ),
				'page'  => 'amsec-network',
			) : null,
			'trusted-proxies' => in_array( $result->evidence['status'] ?? '', array( 'xff', 'single' ), true ) ? array(
				'label' => __( 'Review trusted proxies', 'amazing-security' ),
				'page'  => 'amsec-proxies',
			) : null,
			'security-activity' => 'off' === ( $result->evidence['status'] ?? '' ) ? array(
				'label' => __( 'Review security activity', 'amazing-security' ),
				'page'  => 'amsec-activity',
			) : null,
			'account-sessions' => 'extra' === ( $result->evidence['status'] ?? '' ) ? array(
				'label' => __( 'Review sessions', 'amazing-security' ),
				'page'  => 'amsec-sessions',
			) : null,
			'rule-review' => in_array( $result->evidence['status'] ?? '', array( 'overdue', 'unknown' ), true ) ? array(
				'label' => __( 'Review rule information', 'amazing-security' ),
				'page'  => 'amsec-rules',
			) : null,
			'code-baselines' => in_array( $result->evidence['status'] ?? '', array( 'none', 'preview' ), true ) ? array(
				'label' => __( 'Review code baselines', 'amazing-security' ),
				'page'  => 'amsec-baselines',
			) : null,
			'ai-readers' => State::WARN === $result->state ? array(
				'label'  => 'open' === ( $result->evidence['guest_comments'] ?? '' ) ? __( 'Discussion settings', 'amazing-security' ) : __( 'General settings', 'amazing-security' ),
				'screen' => 'open' === ( $result->evidence['guest_comments'] ?? '' ) ? 'options-discussion.php' : 'options-general.php',
			) : null,
			'ai-readiness' => match ( true ) {
				'on' === ( $result->evidence['assistant'] ?? '' ) => array(
					'label' => __( 'Review AI assistant access', 'amazing-security' ),
					'page'  => 'amsec-assistant',
					'hash'  => 'amsec-mcp',
				),
				'open' === ( $result->evidence['app_passwords'] ?? '' ) => array(
					'label'     => __( 'Pause application passwords', 'amazing-security' ),
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'disable-application-passwords',
				),
				'plugin-off' === ( $result->evidence['app_passwords'] ?? '' ) => array(
					'label'     => __( 'Allow application passwords again', 'amazing-security' ),
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'enable-application-passwords',
				),
				default => null,
			},
			'known-holes' => match ( true ) {
				'no' === $enabled => array(
					'label'  => __( 'Enable vulnerability checks', 'amazing-security' ),
					'action' => 'amazing_security_vulnerability_enable',
					'nonce'  => 'amazing_security_vulnerability_enable',
				),
				'none' === $stored => array(
					'label'  => __( 'Check installed versions', 'amazing-security' ),
					'action' => 'amazing_security_vulnerability_scan',
					'nonce'  => 'amazing_security_vulnerability_scan',
				),
				'found' === $stored => array(
					'label' => __( 'Review vulnerability checks', 'amazing-security' ),
					'page'  => 'amsec-vulnerabilities',
					'hash'  => 'amsec-vulnerabilities',
				),
				default => null,
			},
			'release-files' => match ( $stored ) {
				'none' => array(
					'label'  => __( 'Run integrity scan', 'amazing-security' ),
					'action' => 'amazing_security_integrity_start',
					'nonce'  => 'amazing_security_integrity_start',
				),
				'partial' => array(
					'label'  => __( 'Continue integrity scan', 'amazing-security' ),
					'action' => 'amazing_security_integrity_resume',
					'nonce'  => 'amazing_security_integrity_resume',
					'scan'   => 'integrity',
				),
				'found' => array(
					'label' => __( 'Review integrity scan', 'amazing-security' ),
					'page'  => 'amsec-file-checks',
					'hash'  => 'amsec-integrity',
				),
				default => null,
			},
			'public-content' => match ( $stored ) {
				'none' => array(
					'label'     => __( 'Scan published content', 'amazing-security' ),
					'action'    => 'amsec_content_scan',
					'nonce'     => 'amsec_content_start',
					'operation' => 'start',
				),
				'partial' => array(
					'label'     => __( 'Continue scan', 'amazing-security' ),
					'action'    => 'amsec_content_scan',
					'nonce'     => 'amsec_content_resume',
					'operation' => 'resume',
					'scan'      => 'content',
				),
				'found' => array(
					'label' => __( 'Review content scan', 'amazing-security' ),
					'page'  => 'amsec-content',
				),
				default => null,
			},
			'suspicious-files' => match ( $stored ) {
				'none' => array(
					'label'  => __( 'Run file scan', 'amazing-security' ),
					'action' => 'amazing_security_file_scan_start',
					'nonce'  => 'amazing_security_file_scan_start',
				),
				'partial' => array(
					'label'  => __( 'Continue file scan', 'amazing-security' ),
					'action' => 'amazing_security_file_scan_resume',
					'nonce'  => 'amazing_security_file_scan_resume',
					'scan'   => 'files',
				),
				'found' => array(
					'label' => __( 'Review suspicious files', 'amazing-security' ),
					'page'  => 'amsec-file-checks',
					'hash'  => 'amsec-file-scan',
				),
				default => null,
			},
			'closed-plugins' => in_array( $stored, array( 'none', 'partial', 'found', 'unknown' ), true ) ? array(
				'label' => __( 'Review directory status', 'amazing-security' ),
				'page'  => 'amsec-repository',
			) : null,
			'local-inventory' => in_array( $stored, array( 'none', 'partial', 'found', 'unknown' ), true ) ? array(
				'label' => __( 'Review local inventory', 'amazing-security' ),
				'page'  => 'amsec-exposure',
			) : null,
			'security-headers' => in_array( $stored, array( 'none', 'partial', 'found', 'unknown' ), true ) ? array(
				'label' => __( 'Review security headers', 'amazing-security' ),
				'page'  => 'amsec-headers',
			) : null,
			default => null,
		};
	}
}
