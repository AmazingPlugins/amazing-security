<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

use AmazingPlugins\Security\Findings\CheckResult;
use AmazingPlugins\Security\Findings\State;

/** Fixed first suggestions from a completed local scan. */
final class StartHere {
	public const ORDER = array( 'https-admin', 'core-updates', 'default-admin-login', 'debug-display', 'file-editor', 'login-rate-mode' );
	public const LATER = array( 'uploads-php-execution', 'uploads-php-files', 'file-modes', 'pingbacks', 'xmlrpc-auth', 'captcha-login', 'compromised-passwords', 'login-hints', 'author-archives', 'rest-user-list', 'version-tag', 'discovery-links', 'readme-file', 'license-file', 'debug-log', 'sample-config', 'error-log', 'config-backup', 'php-version', 'background-updates', 'plugin-updates', 'theme-updates', 'inactive-plugins', 'inactive-themes', 'root-exposure', 'bot-controls', 'rest-rates', 'rest-request-watch', 'finding-emails', 'weekly-digest', 'traffic-history', 'network-controls', 'trusted-proxies', 'security-activity', 'account-sessions', 'code-baselines', 'daily-checks', 'daily-file-checks', 'rule-review', 'ai-readers', 'ai-readiness', 'known-holes', 'release-files', 'closed-plugins', 'public-content', 'local-code', 'suspicious-files', 'local-inventory', 'security-headers' );

	public static function label( string $checkId ): string {
		return match ( $checkId ) {
			'https-admin' => 'HTTPS',
			'core-updates' => 'WordPress updates',
			'default-admin-login' => 'Admin login',
			'debug-display' => 'Debug display',
			'file-editor' => 'Theme and plugin editor',
			'login-rate-mode' => 'Login monitoring',
			'uploads-php-execution' => 'PHP in uploads',
			'uploads-php-files' => 'PHP files in uploads',
			'file-modes' => 'File modes',
			'filesystem-permissions' => 'File permissions',
			'pingbacks' => 'Pingbacks',
			'xmlrpc-auth' => 'XML-RPC sign-in',
			'captcha-login' => 'Login CAPTCHA',
			'compromised-passwords' => 'Compromised passwords',
			'login-hints' => 'Login messages',
			'author-archives' => 'Author pages',
			'rest-user-list' => 'REST user list',
			'version-tag' => 'Version tag',
			'discovery-links' => 'Discovery links',
			'readme-file' => 'Readme file',
			'license-file' => 'License file',
			'debug-log' => 'Debug log',
			'sample-config' => 'Sample config',
			'error-log' => 'Error log',
			'config-backup' => 'Config backup',
			'php-version' => 'PHP version',
			'background-updates' => 'Background updates',
			'plugin-updates' => 'Plugin updates',
			'theme-updates' => 'Theme updates',
			'inactive-plugins' => 'Inactive plugins',
			'inactive-themes' => 'Inactive themes',
			'root-exposure' => 'Root files',
			'bot-controls' => 'Bot controls',
			'rest-rates' => 'REST limits',
			'rest-request-watch' => 'REST request watch',
			'finding-emails' => 'Finding emails',
			'weekly-digest' => 'Weekly digest',
			'traffic-history' => 'Traffic history',
			'network-controls' => 'Network controls',
			'trusted-proxies' => 'Trusted proxies',
			'security-activity' => 'Security activity',
			'account-sessions' => 'Account sessions',
			'code-baselines' => 'Code baselines',
			'daily-checks' => 'Daily checks',
			'daily-file-checks' => 'Daily file checks',
			'rule-review' => 'Rule review',
			'ai-readers' => 'Bots and AI readers',
			'ai-readiness' => 'AI security and readiness',
			'known-holes' => 'Known holes',
			'release-files' => 'Release files',
			'closed-plugins' => 'Closed plugins',
			'public-content' => 'Posts and comments',
			'local-code' => 'Local code scan',
			'suspicious-files' => 'Suspicious files',
			'local-inventory' => 'Local inventory',
			'security-headers' => 'Security headers',
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
				'label'  => 'Review plugins',
				'screen' => 'plugins.php',
			) : null,
			'inactive-themes' => State::WARN === $result->state ? array(
				'label'  => 'Review themes',
				'screen' => 'themes.php',
			) : null,
			'https-admin' => State::PASS === $result->state ? null : array(
				'label'  => 'Open Site Health',
				'screen' => 'site-health.php',
			),
			'core-updates', 'plugin-updates', 'theme-updates' => in_array( $result->state, array( State::WARN, State::UNKNOWN ), true ) ? array(
				'label'  => 'Review updates',
				'screen' => 'update-core.php',
			) : null,
			'default-admin-login' => State::WARN === $result->state ? array(
				'label'  => 'Review administrators',
				'screen' => 'users.php',
			) : null,
			'login-rate-mode' => State::PASS === $result->state ? null : array(
				'label' => 'Open login protection',
				'page'  => 'amsec-accounts',
				'hash'  => 'sign-in',
			),
			'authenticator-app' => State::PASS === $result->state ? null : array(
				'label' => 'Open authenticator status',
				'page'  => 'amsec-accounts',
				'hash'  => 'verification',
			),
			'passkeys-status' => State::PASS === $result->state ? null : array(
				'label' => 'Open passkey status',
				'page'  => 'amsec-accounts',
				'hash'  => 'passkeys',
			),
			'pingbacks' => 'open' === ( $result->evidence['status'] ?? '' ) ? array(
				'label'     => 'Turn off pingbacks',
				'action'    => 'amsec_approved_setting',
				'nonce'     => 'amsec_approved_setting',
				'operation' => 'close-pingbacks',
			) : null,
			'debug-display' => match ( $result->evidence['fix'] ?? '' ) {
				'plugin' => State::WARN === $result->state ? array(
					'label'     => 'Hide error details',
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'hide-debug-display',
				) : null,
				'plugin-on' => array(
					'label'     => 'Use the wp-config.php display again',
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'restore-debug-display',
				),
				default => State::PASS === $result->state ? null : array(
					'label'  => 'Open Site Health',
					'screen' => 'site-health.php',
				),
			},
			'file-editor' => match ( $result->evidence['fix'] ?? '' ) {
				'plugin' => State::WARN === $result->state ? array(
					'label'     => 'Turn off the file editor',
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'disable-file-editor',
				) : null,
				'plugin-on' => array(
					'label'     => 'Allow the file editor again',
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'restore-file-editor',
				),
				default => State::PASS === $result->state ? null : array(
					'label' => 'Review the file editor',
					'page'  => 'amsec-recovery',
				),
			},
			'captcha-login' => match ( $result->evidence['status'] ?? '' ) {
				'off' => array(
					'label'     => 'Turn on sign-in confirmation',
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'enable-login-confirm',
				),
				'on' => array(
					'label'     => 'Turn off sign-in confirmation',
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'disable-login-confirm',
				),
				default => null,
			},
			'compromised-passwords' => match ( $result->evidence['status'] ?? '' ) {
				'off' => array(
					'label'     => 'Turn on the local password list',
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'enable-common-passwords',
				),
				'on' => array(
					'label'     => 'Turn off the local password list',
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'disable-common-passwords',
				),
				default => null,
			},
			'login-hints' => match ( $result->evidence['status'] ?? '' ) {
				'off' => array(
					'label'     => 'Use one login message',
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'enable-login-hints',
				),
				'on' => array(
					'label'     => 'Show separate login messages',
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'disable-login-hints',
				),
				default => null,
			},
			'author-archives' => match ( $result->evidence['status'] ?? '' ) {
				'off' => array(
					'label'     => 'Hide author pages',
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'enable-author-archives',
				),
				'on' => array(
					'label'     => 'Show author pages',
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'disable-author-archives',
				),
				default => null,
			},
			'rest-user-list' => match ( $result->evidence['status'] ?? '' ) {
				'off' => array(
					'label'     => 'Require login for the user list',
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'enable-rest-users',
				),
				'on' => array(
					'label'     => 'Allow the public user list',
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'disable-rest-users',
				),
				default => null,
			},
			'version-tag' => match ( $result->evidence['status'] ?? '' ) {
				'off' => array(
					'label'     => 'Hide the version tag',
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'enable-version-tag',
				),
				'on' => array(
					'label'     => 'Show the version tag',
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'disable-version-tag',
				),
				default => null,
			},
			'discovery-links' => match ( $result->evidence['status'] ?? '' ) {
				'off' => array(
					'label'     => 'Remove discovery links',
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'enable-discovery-links',
				),
				'on' => array(
					'label'     => 'Show discovery links',
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'disable-discovery-links',
				),
				default => null,
			},
			'xmlrpc-auth' => 'open' === ( $result->evidence['auth'] ?? '' ) || State::PASS !== $result->state ? array(
				'label' => 'Open login protection',
				'page'  => 'amsec-accounts',
				'hash'  => 'sign-in',
			) : null,
			'uploads-php-execution' => array(
				'label' => 'Review PHP in uploads',
				'page'  => 'amsec-uploads',
			),
			'uploads-php-files' => State::PASS === $result->state ? null : array(
				'label'  => 'Review uploads',
				'screen' => 'upload.php',
			),
			'readme-file', 'license-file', 'debug-log', 'sample-config', 'error-log', 'config-backup', 'root-exposure', 'filesystem-permissions' => State::PASS === $result->state ? null : array(
				'label' => 'Review this finding',
				'page'  => 'amsec-exposure',
			),
			'php-version' => State::PASS === $result->state ? null : array(
				'label'  => 'Open Site Health',
				'screen' => 'site-health.php',
			),
			'background-updates' => State::PASS === $result->state ? null : array(
				'label'  => 'Review updates',
				'screen' => 'update-core.php',
			),
			'daily-checks', 'daily-file-checks' => State::PASS === $result->state ? null : array(
				'label' => 'Review the schedule',
				'page'  => 'amsec-schedule',
				'hash'  => 'amsec-schedule',
			),
			'local-code' => State::PASS === $result->state ? null : array(
				'label' => 'Review the file scan',
				'page'  => 'amsec-file-checks',
				'hash'  => 'amsec-file-scan',
			),
			'file-modes' => in_array( $result->state, array( State::WARN, State::UNKNOWN ), true ) ? array(
				'label' => 'Review file modes',
				'page'  => 'amsec-recovery',
			) : null,
			'bot-controls' => in_array( $result->evidence['mode'] ?? '', array( 'off', 'observe' ), true ) ? array(
				'label' => 'Review bot controls',
				'page'  => 'amsec-bots',
			) : null,
			'rest-rates' => in_array( $result->evidence['mode'] ?? '', array( 'off', 'observe' ), true ) ? array(
				'label' => 'Review REST limits',
				'page'  => 'amsec-rest-rates',
			) : null,
			'rest-request-watch' => 'disabled' === ( $result->evidence['status'] ?? '' ) ? array(
				'label' => 'Open Traffic',
				'page'  => 'amsec-traffic',
			) : null,
			'finding-emails' => 'off' === ( $result->evidence['status'] ?? '' ) ? array(
				'label' => 'Open notification settings',
				'page'  => 'amsec-settings',
				'hash'  => 'amsec-alerts',
			) : null,
			'weekly-digest' => 'off' === ( $result->evidence['status'] ?? '' ) ? array(
				'label' => 'Review weekly digest',
				'page'  => 'amsec-digest',
			) : null,
			'traffic-history' => 'off' === ( $result->evidence['status'] ?? '' ) ? array(
				'label' => 'Review traffic history',
				'page'  => 'amsec-traffic',
			) : null,
			'network-controls' => in_array( $result->evidence['status'] ?? '', array( 'observe', 'block' ), true ) ? array(
				'label' => 'Review network controls',
				'page'  => 'amsec-network',
			) : null,
			'trusted-proxies' => in_array( $result->evidence['status'] ?? '', array( 'xff', 'single' ), true ) ? array(
				'label' => 'Review trusted proxies',
				'page'  => 'amsec-proxies',
			) : null,
			'security-activity' => 'off' === ( $result->evidence['status'] ?? '' ) ? array(
				'label' => 'Review security activity',
				'page'  => 'amsec-activity',
			) : null,
			'account-sessions' => 'extra' === ( $result->evidence['status'] ?? '' ) ? array(
				'label' => 'Review sessions',
				'page'  => 'amsec-sessions',
			) : null,
			'rule-review' => in_array( $result->evidence['status'] ?? '', array( 'overdue', 'unknown' ), true ) ? array(
				'label' => 'Review rule information',
				'page'  => 'amsec-rules',
			) : null,
			'code-baselines' => in_array( $result->evidence['status'] ?? '', array( 'none', 'preview' ), true ) ? array(
				'label' => 'Review code baselines',
				'page'  => 'amsec-baselines',
			) : null,
			'ai-readers' => State::WARN === $result->state ? array(
				'label'  => 'open' === ( $result->evidence['guest_comments'] ?? '' ) ? 'Discussion settings' : 'General settings',
				'screen' => 'open' === ( $result->evidence['guest_comments'] ?? '' ) ? 'options-discussion.php' : 'options-general.php',
			) : null,
			'ai-readiness' => match ( true ) {
				'on' === ( $result->evidence['assistant'] ?? '' ) => array(
					'label' => 'Review AI assistant access',
					'page'  => 'amsec-assistant',
					'hash'  => 'amsec-mcp',
				),
				'open' === ( $result->evidence['app_passwords'] ?? '' ) => array(
					'label'     => 'Pause application passwords',
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'disable-application-passwords',
				),
				'plugin-off' === ( $result->evidence['app_passwords'] ?? '' ) => array(
					'label'     => 'Allow application passwords again',
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'enable-application-passwords',
				),
				default => null,
			},
			'known-holes' => match ( true ) {
				'no' === $enabled => array(
					'label'  => 'Enable vulnerability checks',
					'action' => 'amazing_security_vulnerability_enable',
					'nonce'  => 'amazing_security_vulnerability_enable',
				),
				'none' === $stored => array(
					'label'  => 'Check installed versions',
					'action' => 'amazing_security_vulnerability_scan',
					'nonce'  => 'amazing_security_vulnerability_scan',
				),
				'found' === $stored => array(
					'label' => 'Review vulnerability checks',
					'page'  => 'amsec-vulnerabilities',
					'hash'  => 'amsec-vulnerabilities',
				),
				default => null,
			},
			'release-files' => match ( $stored ) {
				'none' => array(
					'label'  => 'Run integrity scan',
					'action' => 'amazing_security_integrity_start',
					'nonce'  => 'amazing_security_integrity_start',
				),
				'partial' => array(
					'label'  => 'Continue integrity scan',
					'action' => 'amazing_security_integrity_resume',
					'nonce'  => 'amazing_security_integrity_resume',
					'scan'   => 'integrity',
				),
				'found' => array(
					'label' => 'Review integrity scan',
					'page'  => 'amsec-file-checks',
					'hash'  => 'amsec-integrity',
				),
				default => null,
			},
			'public-content' => match ( $stored ) {
				'none' => array(
					'label'     => 'Scan published content',
					'action'    => 'amsec_content_scan',
					'nonce'     => 'amsec_content_start',
					'operation' => 'start',
				),
				'partial' => array(
					'label'     => 'Continue scan',
					'action'    => 'amsec_content_scan',
					'nonce'     => 'amsec_content_resume',
					'operation' => 'resume',
					'scan'      => 'content',
				),
				'found' => array(
					'label' => 'Review content scan',
					'page'  => 'amsec-content',
				),
				default => null,
			},
			'suspicious-files' => match ( $stored ) {
				'none' => array(
					'label'  => 'Run file scan',
					'action' => 'amazing_security_file_scan_start',
					'nonce'  => 'amazing_security_file_scan_start',
				),
				'partial' => array(
					'label'  => 'Continue file scan',
					'action' => 'amazing_security_file_scan_resume',
					'nonce'  => 'amazing_security_file_scan_resume',
					'scan'   => 'files',
				),
				'found' => array(
					'label' => 'Review suspicious files',
					'page'  => 'amsec-file-checks',
					'hash'  => 'amsec-file-scan',
				),
				default => null,
			},
			'closed-plugins' => in_array( $stored, array( 'none', 'partial', 'found', 'unknown' ), true ) ? array(
				'label' => 'Review directory status',
				'page'  => 'amsec-repository',
			) : null,
			'local-inventory' => in_array( $stored, array( 'none', 'partial', 'found', 'unknown' ), true ) ? array(
				'label' => 'Review local inventory',
				'page'  => 'amsec-exposure',
			) : null,
			'security-headers' => in_array( $stored, array( 'none', 'partial', 'found', 'unknown' ), true ) ? array(
				'label' => 'Review security headers',
				'page'  => 'amsec-headers',
			) : null,
			default => null,
		};
	}
}
