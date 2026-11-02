<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Findings\CheckResult;
use AmazingPlugins\Security\Findings\State;
use AmazingPlugins\Security\Login\RequiredTotpPage;

/** Fixed first suggestions from a completed local scan. */
final class StartHere {
	public const ORDER = array( 'https-admin', 'core-updates', 'default-admin-login', 'debug-display', 'file-editor', 'login-rate-mode' );
	public const LATER = array( 'uploads-php-execution', 'uploads-php-files', 'file-modes', 'pingbacks', 'xmlrpc-auth', 'captcha-login', 'compromised-passwords', 'login-hints', 'author-archives', 'rest-user-list', 'version-tag', 'discovery-links', 'readme-file', 'license-file', 'debug-log', 'sample-config', 'error-log', 'config-backup', 'php-version', 'background-updates', 'plugin-updates', 'theme-updates', 'inactive-plugins', 'inactive-themes', 'root-exposure', 'bot-controls', 'rest-rates', 'rest-request-watch', 'finding-emails', 'weekly-digest', 'traffic-history', 'network-controls', 'trusted-proxies', 'security-activity', 'account-sessions', 'code-baselines', 'daily-checks', 'daily-file-checks', 'rule-review', 'ai-readers', 'ai-readiness', 'known-holes', 'release-files', 'closed-plugins', 'public-content', 'local-code', 'suspicious-files', 'local-inventory', 'security-headers' );

	public static function label( string $checkId ): string {
		return match ( $checkId ) {
			'https-admin' => __( 'HTTPS', 'ironlatch-security-scanner' ),
			'core-updates' => __( 'WordPress updates', 'ironlatch-security-scanner' ),
			'default-admin-login' => __( 'Admin login', 'ironlatch-security-scanner' ),
			'debug-display' => __( 'Debug display', 'ironlatch-security-scanner' ),
			'file-editor' => __( 'Theme and plugin editor', 'ironlatch-security-scanner' ),
			'login-rate-mode' => __( 'Login monitoring', 'ironlatch-security-scanner' ),
			'uploads-php-execution' => __( 'PHP in uploads', 'ironlatch-security-scanner' ),
			'uploads-php-files' => __( 'PHP files in uploads', 'ironlatch-security-scanner' ),
			'file-modes' => __( 'File modes', 'ironlatch-security-scanner' ),
			'filesystem-permissions' => __( 'File permissions', 'ironlatch-security-scanner' ),
			'pingbacks' => __( 'Pingbacks', 'ironlatch-security-scanner' ),
			'xmlrpc-auth' => __( 'XML-RPC sign-in', 'ironlatch-security-scanner' ),
			'captcha-login' => __( 'Login bot trap', 'ironlatch-security-scanner' ),
			'compromised-passwords' => __( 'Compromised passwords', 'ironlatch-security-scanner' ),
			'login-hints' => __( 'Login messages', 'ironlatch-security-scanner' ),
			'author-archives' => __( 'Author pages', 'ironlatch-security-scanner' ),
			'rest-user-list' => __( 'REST user list', 'ironlatch-security-scanner' ),
			'version-tag' => __( 'Version tag', 'ironlatch-security-scanner' ),
			'discovery-links' => __( 'Discovery links', 'ironlatch-security-scanner' ),
			'readme-file' => __( 'Readme file', 'ironlatch-security-scanner' ),
			'license-file' => __( 'License file', 'ironlatch-security-scanner' ),
			'debug-log' => __( 'Debug log', 'ironlatch-security-scanner' ),
			'sample-config' => __( 'Sample config', 'ironlatch-security-scanner' ),
			'error-log' => __( 'Error log', 'ironlatch-security-scanner' ),
			'config-backup' => __( 'Config backup', 'ironlatch-security-scanner' ),
			'php-version' => __( 'PHP version', 'ironlatch-security-scanner' ),
			'background-updates' => __( 'Background updates', 'ironlatch-security-scanner' ),
			'plugin-updates' => __( 'Plugin updates', 'ironlatch-security-scanner' ),
			'theme-updates' => __( 'Theme updates', 'ironlatch-security-scanner' ),
			'inactive-plugins' => __( 'Inactive plugins', 'ironlatch-security-scanner' ),
			'inactive-themes' => __( 'Inactive themes', 'ironlatch-security-scanner' ),
			'root-exposure' => __( 'Root files', 'ironlatch-security-scanner' ),
			'bot-controls' => __( 'Bot controls', 'ironlatch-security-scanner' ),
			'rest-rates' => __( 'REST limits', 'ironlatch-security-scanner' ),
			'rest-request-watch' => __( 'REST request watch', 'ironlatch-security-scanner' ),
			'finding-emails' => __( 'Finding emails', 'ironlatch-security-scanner' ),
			'weekly-digest' => __( 'Weekly digest', 'ironlatch-security-scanner' ),
			'traffic-history' => __( 'Traffic history', 'ironlatch-security-scanner' ),
			'network-controls' => __( 'Network controls', 'ironlatch-security-scanner' ),
			'trusted-proxies' => __( 'Trusted proxies', 'ironlatch-security-scanner' ),
			'security-activity' => __( 'Security activity', 'ironlatch-security-scanner' ),
			'account-sessions' => __( 'Account sessions', 'ironlatch-security-scanner' ),
			'code-baselines' => __( 'Code baselines', 'ironlatch-security-scanner' ),
			'daily-checks' => __( 'Daily checks', 'ironlatch-security-scanner' ),
			'daily-file-checks' => __( 'Daily file checks', 'ironlatch-security-scanner' ),
			'rule-review' => __( 'Rule review', 'ironlatch-security-scanner' ),
			'ai-readers' => __( 'Bots and AI readers', 'ironlatch-security-scanner' ),
			'ai-readiness' => __( 'AI security and readiness', 'ironlatch-security-scanner' ),
			'known-holes' => __( 'Known holes', 'ironlatch-security-scanner' ),
			'release-files' => __( 'Release files', 'ironlatch-security-scanner' ),
			'closed-plugins' => __( 'Closed plugins', 'ironlatch-security-scanner' ),
			'public-content' => __( 'Posts and comments', 'ironlatch-security-scanner' ),
			'local-code' => __( 'Malware scan', 'ironlatch-security-scanner' ),
			'authenticator-app' => __( 'Authenticator app', 'ironlatch-security-scanner' ),
			'passkeys-status' => __( 'Passkeys', 'ironlatch-security-scanner' ),
			'suspicious-files' => __( 'Suspicious files', 'ironlatch-security-scanner' ),
			'local-inventory' => __( 'Local inventory', 'ironlatch-security-scanner' ),
			'security-headers' => __( 'Security headers', 'ironlatch-security-scanner' ),
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
		$status  = is_string( $result->evidence['status'] ?? null ) ? $result->evidence['status'] : '';
		return match ( $result->checkId ) {
			'inactive-plugins' => State::WARN === $result->state ? array(
				'label'  => __( 'Review plugins', 'ironlatch-security-scanner' ),
				'screen' => 'plugins.php',
			) : null,
			'inactive-themes' => State::WARN === $result->state ? array(
				'label'  => __( 'Review themes', 'ironlatch-security-scanner' ),
				'screen' => 'themes.php',
			) : null,
			'https-admin' => State::PASS === $result->state ? null : array(
				'label'  => __( 'Open Site Health', 'ironlatch-security-scanner' ),
				'screen' => 'site-health.php',
			),
			'core-updates', 'plugin-updates', 'theme-updates' => in_array( $result->state, array( State::WARN, State::UNKNOWN ), true ) ? array(
				'label'  => __( 'Review updates', 'ironlatch-security-scanner' ),
				'screen' => 'update-core.php',
			) : null,
			'default-admin-login' => State::WARN === $result->state ? array(
				'label'  => __( 'Review administrators', 'ironlatch-security-scanner' ),
				'screen' => 'users.php',
			) : null,
			'login-rate-mode' => State::PASS === $result->state ? null : array(
				'label' => __( 'Open login protection', 'ironlatch-security-scanner' ),
				'page'  => 'ironlatch-accounts',
				'hash'  => 'sign-in',
			),
			'authenticator-app', 'passkeys-status' => match ( true ) {
				State::PASS === $result->state => null,
				'missing' === $status => array(
					'label'   => RequiredTotpPage::installed( 'two-factor' ) && current_user_can( 'activate_plugins' ) ? __( 'Activate Two Factor', 'ironlatch-security-scanner' ) : __( 'Find Two Factor', 'ironlatch-security-scanner' ),
					'install' => 'two-factor',
				),
				'passkeys-status' === $result->checkId => array(
					'label' => __( 'Open passkey status', 'ironlatch-security-scanner' ),
					'page'  => 'ironlatch-accounts',
					'hash'  => 'passkeys',
				),
				default => array(
					'label' => __( 'Open authenticator status', 'ironlatch-security-scanner' ),
					'page'  => 'ironlatch-accounts',
					'hash'  => 'verification',
				),
			},
			'pingbacks' => 'open' === ( $result->evidence['status'] ?? '' ) ? array(
				'label'     => __( 'Turn off pingbacks', 'ironlatch-security-scanner' ),
				'action'    => 'ironlatch_approved_setting',
				'nonce'     => 'ironlatch_approved_setting',
				'operation' => 'close-pingbacks',
			) : null,
			'debug-display' => match ( $result->evidence['fix'] ?? '' ) {
				'plugin' => State::WARN === $result->state ? array(
					'label'     => __( 'Hide error details', 'ironlatch-security-scanner' ),
					'action'    => 'ironlatch_approved_setting',
					'nonce'     => 'ironlatch_approved_setting',
					'operation' => 'hide-debug-display',
				) : null,
				'plugin-on' => array(
					'label'     => __( 'Use the wp-config.php display again', 'ironlatch-security-scanner' ),
					'action'    => 'ironlatch_approved_setting',
					'nonce'     => 'ironlatch_approved_setting',
					'operation' => 'restore-debug-display',
				),
				default => State::PASS === $result->state ? null : array(
					'label'  => __( 'Open Site Health', 'ironlatch-security-scanner' ),
					'screen' => 'site-health.php',
				),
			},
			'file-editor' => match ( $result->evidence['fix'] ?? '' ) {
				'plugin' => State::WARN === $result->state ? array(
					'label'     => __( 'Turn off the file editor', 'ironlatch-security-scanner' ),
					'action'    => 'ironlatch_approved_setting',
					'nonce'     => 'ironlatch_approved_setting',
					'operation' => 'disable-file-editor',
				) : null,
				'plugin-on' => array(
					'label'     => __( 'Allow the file editor again', 'ironlatch-security-scanner' ),
					'action'    => 'ironlatch_approved_setting',
					'nonce'     => 'ironlatch_approved_setting',
					'operation' => 'restore-file-editor',
				),
				default => State::PASS === $result->state ? null : array(
					'label' => __( 'Review the file editor', 'ironlatch-security-scanner' ),
					'page'  => 'ironlatch-recovery',
				),
			},
			'captcha-login' => match ( $result->evidence['status'] ?? '' ) {
				'off' => array(
					'label'     => __( 'Turn on the bot trap', 'ironlatch-security-scanner' ),
					'action'    => 'ironlatch_approved_setting',
					'nonce'     => 'ironlatch_approved_setting',
					'operation' => 'enable-login-confirm',
				),
				'on' => array(
					'label'     => __( 'Turn off the bot trap', 'ironlatch-security-scanner' ),
					'action'    => 'ironlatch_approved_setting',
					'nonce'     => 'ironlatch_approved_setting',
					'operation' => 'disable-login-confirm',
				),
				default => null,
			},
			'compromised-passwords' => match ( $result->evidence['status'] ?? '' ) {
				'off' => array(
					'label'     => __( 'Turn on breached-password checks', 'ironlatch-security-scanner' ),
					'action'    => 'ironlatch_approved_setting',
					'nonce'     => 'ironlatch_approved_setting',
					'operation' => 'enable-common-passwords',
				),
				'on' => array(
					'label'     => __( 'Turn off breached-password checks', 'ironlatch-security-scanner' ),
					'action'    => 'ironlatch_approved_setting',
					'nonce'     => 'ironlatch_approved_setting',
					'operation' => 'disable-common-passwords',
				),
				default => null,
			},
			'login-hints' => match ( $result->evidence['status'] ?? '' ) {
				'off' => array(
					'label'     => __( 'Use one login message', 'ironlatch-security-scanner' ),
					'action'    => 'ironlatch_approved_setting',
					'nonce'     => 'ironlatch_approved_setting',
					'operation' => 'enable-login-hints',
				),
				'on' => array(
					'label'     => __( 'Show separate login messages', 'ironlatch-security-scanner' ),
					'action'    => 'ironlatch_approved_setting',
					'nonce'     => 'ironlatch_approved_setting',
					'operation' => 'disable-login-hints',
				),
				default => null,
			},
			'author-archives' => match ( $result->evidence['status'] ?? '' ) {
				'off' => array(
					'label'     => __( 'Hide author pages', 'ironlatch-security-scanner' ),
					'action'    => 'ironlatch_approved_setting',
					'nonce'     => 'ironlatch_approved_setting',
					'operation' => 'enable-author-archives',
				),
				'on' => array(
					'label'     => __( 'Show author pages', 'ironlatch-security-scanner' ),
					'action'    => 'ironlatch_approved_setting',
					'nonce'     => 'ironlatch_approved_setting',
					'operation' => 'disable-author-archives',
				),
				default => null,
			},
			'rest-user-list' => match ( $result->evidence['status'] ?? '' ) {
				'off' => array(
					'label'     => __( 'Require login for the user list', 'ironlatch-security-scanner' ),
					'action'    => 'ironlatch_approved_setting',
					'nonce'     => 'ironlatch_approved_setting',
					'operation' => 'enable-rest-users',
				),
				'on' => array(
					'label'     => __( 'Allow the public user list', 'ironlatch-security-scanner' ),
					'action'    => 'ironlatch_approved_setting',
					'nonce'     => 'ironlatch_approved_setting',
					'operation' => 'disable-rest-users',
				),
				default => null,
			},
			'version-tag' => match ( $result->evidence['status'] ?? '' ) {
				'off' => array(
					'label'     => __( 'Hide the version tag', 'ironlatch-security-scanner' ),
					'action'    => 'ironlatch_approved_setting',
					'nonce'     => 'ironlatch_approved_setting',
					'operation' => 'enable-version-tag',
				),
				'on' => array(
					'label'     => __( 'Show the version tag', 'ironlatch-security-scanner' ),
					'action'    => 'ironlatch_approved_setting',
					'nonce'     => 'ironlatch_approved_setting',
					'operation' => 'disable-version-tag',
				),
				default => null,
			},
			'discovery-links' => match ( $result->evidence['status'] ?? '' ) {
				'off' => array(
					'label'     => __( 'Remove discovery links', 'ironlatch-security-scanner' ),
					'action'    => 'ironlatch_approved_setting',
					'nonce'     => 'ironlatch_approved_setting',
					'operation' => 'enable-discovery-links',
				),
				'on' => array(
					'label'     => __( 'Show discovery links', 'ironlatch-security-scanner' ),
					'action'    => 'ironlatch_approved_setting',
					'nonce'     => 'ironlatch_approved_setting',
					'operation' => 'disable-discovery-links',
				),
				default => null,
			},
			'xmlrpc-auth' => 'open' === ( $result->evidence['auth'] ?? '' ) || State::PASS !== $result->state ? array(
				'label' => __( 'Open login protection', 'ironlatch-security-scanner' ),
				'page'  => 'ironlatch-accounts',
				'hash'  => 'sign-in',
			) : null,
			'uploads-php-execution' => array(
				'label' => __( 'Review PHP in uploads', 'ironlatch-security-scanner' ),
				'page'  => 'ironlatch-uploads',
			),
			'uploads-php-files' => State::PASS === $result->state ? null : array(
				'label'  => __( 'Review uploads', 'ironlatch-security-scanner' ),
				'screen' => 'upload.php',
			),
			'readme-file', 'license-file', 'debug-log', 'sample-config', 'error-log', 'config-backup', 'root-exposure', 'filesystem-permissions' => State::PASS === $result->state ? null : array(
				'label' => __( 'Review this finding', 'ironlatch-security-scanner' ),
				'page'  => 'ironlatch-exposure',
			),
			'php-version' => State::PASS === $result->state ? null : array(
				'label'  => __( 'Open Site Health', 'ironlatch-security-scanner' ),
				'screen' => 'site-health.php',
			),
			'background-updates' => State::PASS === $result->state ? null : array(
				'label'  => __( 'Review updates', 'ironlatch-security-scanner' ),
				'screen' => 'update-core.php',
			),
			'daily-checks', 'daily-file-checks' => State::PASS === $result->state ? null : array(
				'label' => __( 'Review the schedule', 'ironlatch-security-scanner' ),
				'page'  => 'ironlatch-schedule',
				'hash'  => 'ironlatch-schedule',
			),
			'local-code' => State::PASS === $result->state ? null : array(
				'label' => __( 'Review malware findings', 'ironlatch-security-scanner' ),
				'page'  => 'ironlatch-file-checks',
				'hash'  => 'ironlatch-malware',
			),
			'file-modes' => in_array( $result->state, array( State::WARN, State::UNKNOWN ), true ) ? array(
				'label' => __( 'Review file modes', 'ironlatch-security-scanner' ),
				'page'  => 'ironlatch-recovery',
			) : null,
			'bot-controls' => in_array( $result->evidence['mode'] ?? '', array( 'off', 'observe' ), true ) ? array(
				'label' => __( 'Review bot controls', 'ironlatch-security-scanner' ),
				'page'  => 'ironlatch-bots',
			) : null,
			'rest-rates' => in_array( $result->evidence['mode'] ?? '', array( 'off', 'observe' ), true ) ? array(
				'label' => __( 'Review REST limits', 'ironlatch-security-scanner' ),
				'page'  => 'ironlatch-rest-rates',
			) : null,
			'rest-request-watch' => 'disabled' === ( $result->evidence['status'] ?? '' ) ? array(
				'label' => __( 'Open Traffic', 'ironlatch-security-scanner' ),
				'page'  => 'ironlatch-traffic',
			) : null,
			'finding-emails' => 'off' === ( $result->evidence['status'] ?? '' ) ? array(
				'label' => __( 'Open notification settings', 'ironlatch-security-scanner' ),
				'page'  => 'ironlatch-settings',
				'hash'  => 'ironlatch-alerts',
			) : null,
			'weekly-digest' => 'off' === ( $result->evidence['status'] ?? '' ) ? array(
				'label' => __( 'Review weekly digest', 'ironlatch-security-scanner' ),
				'page'  => 'ironlatch-digest',
			) : null,
			'traffic-history' => 'off' === ( $result->evidence['status'] ?? '' ) ? array(
				'label' => __( 'Review traffic history', 'ironlatch-security-scanner' ),
				'page'  => 'ironlatch-traffic',
			) : null,
			'network-controls' => in_array( $result->evidence['status'] ?? '', array( 'observe', 'block' ), true ) ? array(
				'label' => __( 'Review network controls', 'ironlatch-security-scanner' ),
				'page'  => 'ironlatch-network',
			) : null,
			'trusted-proxies' => in_array( $result->evidence['status'] ?? '', array( 'xff', 'single' ), true ) ? array(
				'label' => __( 'Review trusted proxies', 'ironlatch-security-scanner' ),
				'page'  => 'ironlatch-proxies',
			) : null,
			'security-activity' => 'off' === ( $result->evidence['status'] ?? '' ) ? array(
				'label' => __( 'Review security activity', 'ironlatch-security-scanner' ),
				'page'  => 'ironlatch-activity',
			) : null,
			'account-sessions' => 'extra' === ( $result->evidence['status'] ?? '' ) ? array(
				'label' => __( 'Review sessions', 'ironlatch-security-scanner' ),
				'page'  => 'ironlatch-sessions',
			) : null,
			'rule-review' => in_array( $result->evidence['status'] ?? '', array( 'overdue', 'unknown' ), true ) ? array(
				'label' => __( 'Review rule information', 'ironlatch-security-scanner' ),
				'page'  => 'ironlatch-rules',
			) : null,
			'code-baselines' => in_array( $result->evidence['status'] ?? '', array( 'none', 'preview' ), true ) ? array(
				'label' => __( 'Review code baselines', 'ironlatch-security-scanner' ),
				'page'  => 'ironlatch-baselines',
			) : null,
			'ai-readers' => State::WARN === $result->state ? array(
				'label'  => 'open' === ( $result->evidence['guest_comments'] ?? '' ) ? __( 'Discussion settings', 'ironlatch-security-scanner' ) : __( 'General settings', 'ironlatch-security-scanner' ),
				'screen' => 'open' === ( $result->evidence['guest_comments'] ?? '' ) ? 'options-discussion.php' : 'options-general.php',
			) : null,
			'ai-readiness' => match ( true ) {
				'on' === ( $result->evidence['assistant'] ?? '' ) => array(
					'label' => __( 'Review AI assistant access', 'ironlatch-security-scanner' ),
					'page'  => 'ironlatch-assistant',
					'hash'  => 'ironlatch-mcp',
				),
				'open' === ( $result->evidence['app_passwords'] ?? '' ) => array(
					'label'     => __( 'Pause application passwords', 'ironlatch-security-scanner' ),
					'action'    => 'ironlatch_approved_setting',
					'nonce'     => 'ironlatch_approved_setting',
					'operation' => 'disable-application-passwords',
				),
				'plugin-off' === ( $result->evidence['app_passwords'] ?? '' ) => array(
					'label'     => __( 'Allow application passwords again', 'ironlatch-security-scanner' ),
					'action'    => 'ironlatch_approved_setting',
					'nonce'     => 'ironlatch_approved_setting',
					'operation' => 'enable-application-passwords',
				),
				default => null,
			},
			'known-holes' => match ( true ) {
				'no' === $enabled => array(
					'label'  => __( 'Enable vulnerability checks', 'ironlatch-security-scanner' ),
					'action' => 'ironlatch_security_scanner_vulnerability_enable',
					'nonce'  => 'ironlatch_security_scanner_vulnerability_enable',
				),
				'none' === $stored => array(
					'label'  => __( 'Check installed versions', 'ironlatch-security-scanner' ),
					'action' => 'ironlatch_security_scanner_vulnerability_scan',
					'nonce'  => 'ironlatch_security_scanner_vulnerability_scan',
				),
				'found' === $stored => array(
					'label' => __( 'Review vulnerability checks', 'ironlatch-security-scanner' ),
					'page'  => 'ironlatch-vulnerabilities',
					'hash'  => 'ironlatch-vulnerabilities',
				),
				default => null,
			},
			'release-files' => match ( $stored ) {
				'none' => array(
					'label'  => __( 'Run integrity scan', 'ironlatch-security-scanner' ),
					'action' => 'ironlatch_security_scanner_integrity_start',
					'nonce'  => 'ironlatch_security_scanner_integrity_start',
				),
				'partial' => array(
					'label'  => __( 'Continue integrity scan', 'ironlatch-security-scanner' ),
					'action' => 'ironlatch_security_scanner_integrity_resume',
					'nonce'  => 'ironlatch_security_scanner_integrity_resume',
					'scan'   => 'integrity',
				),
				'found' => array(
					'label' => __( 'Review integrity scan', 'ironlatch-security-scanner' ),
					'page'  => 'ironlatch-file-checks',
					'hash'  => 'ironlatch-integrity',
				),
				default => null,
			},
			'public-content' => match ( $stored ) {
				'none' => array(
					'label'     => __( 'Scan published content', 'ironlatch-security-scanner' ),
					'action'    => 'ironlatch_content_scan',
					'nonce'     => 'ironlatch_content_start',
					'operation' => 'start',
				),
				'partial' => array(
					'label'     => __( 'Continue scan', 'ironlatch-security-scanner' ),
					'action'    => 'ironlatch_content_scan',
					'nonce'     => 'ironlatch_content_resume',
					'operation' => 'resume',
					'scan'      => 'content',
				),
				'found' => array(
					'label' => __( 'Review content scan', 'ironlatch-security-scanner' ),
					'page'  => 'ironlatch-content',
				),
				default => null,
			},
			'suspicious-files' => match ( $stored ) {
				'none' => array(
					'label'  => __( 'Run file scan', 'ironlatch-security-scanner' ),
					'action' => 'ironlatch_security_scanner_file_scan_start',
					'nonce'  => 'ironlatch_security_scanner_file_scan_start',
				),
				'partial' => array(
					'label'  => __( 'Continue file scan', 'ironlatch-security-scanner' ),
					'action' => 'ironlatch_security_scanner_file_scan_resume',
					'nonce'  => 'ironlatch_security_scanner_file_scan_resume',
					'scan'   => 'files',
				),
				'found' => array(
					'label' => __( 'Review suspicious files', 'ironlatch-security-scanner' ),
					'page'  => 'ironlatch-file-checks',
					'hash'  => 'ironlatch-file-scan',
				),
				default => null,
			},
			'closed-plugins' => in_array( $stored, array( 'none', 'partial', 'found', 'unknown' ), true ) ? array(
				'label' => __( 'Review directory status', 'ironlatch-security-scanner' ),
				'page'  => 'ironlatch-repository',
			) : null,
			'local-inventory' => in_array( $stored, array( 'none', 'partial', 'found', 'unknown' ), true ) ? array(
				'label' => __( 'Review local inventory', 'ironlatch-security-scanner' ),
				'page'  => 'ironlatch-exposure',
			) : null,
			'security-headers' => in_array( $stored, array( 'none', 'partial', 'found', 'unknown' ), true ) ? array(
				'label' => __( 'Review security headers', 'ironlatch-security-scanner' ),
				'page'  => 'ironlatch-headers',
			) : null,
			default => null,
		};
	}
}
