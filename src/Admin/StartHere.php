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
			'https-admin' => __( 'HTTPS', 'amsec-security-scanner' ),
			'core-updates' => __( 'WordPress updates', 'amsec-security-scanner' ),
			'default-admin-login' => __( 'Admin login', 'amsec-security-scanner' ),
			'debug-display' => __( 'Debug display', 'amsec-security-scanner' ),
			'file-editor' => __( 'Theme and plugin editor', 'amsec-security-scanner' ),
			'login-rate-mode' => __( 'Login monitoring', 'amsec-security-scanner' ),
			'uploads-php-execution' => __( 'PHP in uploads', 'amsec-security-scanner' ),
			'uploads-php-files' => __( 'PHP files in uploads', 'amsec-security-scanner' ),
			'file-modes' => __( 'File modes', 'amsec-security-scanner' ),
			'filesystem-permissions' => __( 'File permissions', 'amsec-security-scanner' ),
			'pingbacks' => __( 'Pingbacks', 'amsec-security-scanner' ),
			'xmlrpc-auth' => __( 'XML-RPC sign-in', 'amsec-security-scanner' ),
			'captcha-login' => __( 'Login bot trap', 'amsec-security-scanner' ),
			'compromised-passwords' => __( 'Compromised passwords', 'amsec-security-scanner' ),
			'login-hints' => __( 'Login messages', 'amsec-security-scanner' ),
			'author-archives' => __( 'Author pages', 'amsec-security-scanner' ),
			'rest-user-list' => __( 'REST user list', 'amsec-security-scanner' ),
			'version-tag' => __( 'Version tag', 'amsec-security-scanner' ),
			'discovery-links' => __( 'Discovery links', 'amsec-security-scanner' ),
			'readme-file' => __( 'Readme file', 'amsec-security-scanner' ),
			'license-file' => __( 'License file', 'amsec-security-scanner' ),
			'debug-log' => __( 'Debug log', 'amsec-security-scanner' ),
			'sample-config' => __( 'Sample config', 'amsec-security-scanner' ),
			'error-log' => __( 'Error log', 'amsec-security-scanner' ),
			'config-backup' => __( 'Config backup', 'amsec-security-scanner' ),
			'php-version' => __( 'PHP version', 'amsec-security-scanner' ),
			'background-updates' => __( 'Background updates', 'amsec-security-scanner' ),
			'plugin-updates' => __( 'Plugin updates', 'amsec-security-scanner' ),
			'theme-updates' => __( 'Theme updates', 'amsec-security-scanner' ),
			'inactive-plugins' => __( 'Inactive plugins', 'amsec-security-scanner' ),
			'inactive-themes' => __( 'Inactive themes', 'amsec-security-scanner' ),
			'root-exposure' => __( 'Root files', 'amsec-security-scanner' ),
			'bot-controls' => __( 'Bot controls', 'amsec-security-scanner' ),
			'rest-rates' => __( 'REST limits', 'amsec-security-scanner' ),
			'rest-request-watch' => __( 'REST request watch', 'amsec-security-scanner' ),
			'finding-emails' => __( 'Finding emails', 'amsec-security-scanner' ),
			'weekly-digest' => __( 'Weekly digest', 'amsec-security-scanner' ),
			'traffic-history' => __( 'Traffic history', 'amsec-security-scanner' ),
			'network-controls' => __( 'Network controls', 'amsec-security-scanner' ),
			'trusted-proxies' => __( 'Trusted proxies', 'amsec-security-scanner' ),
			'security-activity' => __( 'Security activity', 'amsec-security-scanner' ),
			'account-sessions' => __( 'Account sessions', 'amsec-security-scanner' ),
			'code-baselines' => __( 'Code baselines', 'amsec-security-scanner' ),
			'daily-checks' => __( 'Daily checks', 'amsec-security-scanner' ),
			'daily-file-checks' => __( 'Daily file checks', 'amsec-security-scanner' ),
			'rule-review' => __( 'Rule review', 'amsec-security-scanner' ),
			'ai-readers' => __( 'Bots and AI readers', 'amsec-security-scanner' ),
			'ai-readiness' => __( 'AI security and readiness', 'amsec-security-scanner' ),
			'known-holes' => __( 'Known holes', 'amsec-security-scanner' ),
			'release-files' => __( 'Release files', 'amsec-security-scanner' ),
			'closed-plugins' => __( 'Closed plugins', 'amsec-security-scanner' ),
			'public-content' => __( 'Posts and comments', 'amsec-security-scanner' ),
			'local-code' => __( 'Malware scan', 'amsec-security-scanner' ),
			'authenticator-app' => __( 'Authenticator app', 'amsec-security-scanner' ),
			'passkeys-status' => __( 'Passkeys', 'amsec-security-scanner' ),
			'suspicious-files' => __( 'Suspicious files', 'amsec-security-scanner' ),
			'local-inventory' => __( 'Local inventory', 'amsec-security-scanner' ),
			'security-headers' => __( 'Security headers', 'amsec-security-scanner' ),
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
				'label'  => __( 'Review plugins', 'amsec-security-scanner' ),
				'screen' => 'plugins.php',
			) : null,
			'inactive-themes' => State::WARN === $result->state ? array(
				'label'  => __( 'Review themes', 'amsec-security-scanner' ),
				'screen' => 'themes.php',
			) : null,
			'https-admin' => State::PASS === $result->state ? null : array(
				'label'  => __( 'Open Site Health', 'amsec-security-scanner' ),
				'screen' => 'site-health.php',
			),
			'core-updates', 'plugin-updates', 'theme-updates' => in_array( $result->state, array( State::WARN, State::UNKNOWN ), true ) ? array(
				'label'  => __( 'Review updates', 'amsec-security-scanner' ),
				'screen' => 'update-core.php',
			) : null,
			'default-admin-login' => State::WARN === $result->state ? array(
				'label'  => __( 'Review administrators', 'amsec-security-scanner' ),
				'screen' => 'users.php',
			) : null,
			'login-rate-mode' => State::PASS === $result->state ? null : array(
				'label' => __( 'Open login protection', 'amsec-security-scanner' ),
				'page'  => 'amsec-accounts',
				'hash'  => 'sign-in',
			),
			'authenticator-app', 'passkeys-status' => match ( true ) {
				State::PASS === $result->state => null,
				'missing' === $status => array(
					'label'   => RequiredTotpPage::installed( 'two-factor' ) && current_user_can( 'activate_plugins' ) ? __( 'Activate Two Factor', 'amsec-security-scanner' ) : __( 'Find Two Factor', 'amsec-security-scanner' ),
					'install' => 'two-factor',
				),
				'passkeys-status' === $result->checkId => array(
					'label' => __( 'Open passkey status', 'amsec-security-scanner' ),
					'page'  => 'amsec-accounts',
					'hash'  => 'passkeys',
				),
				default => array(
					'label' => __( 'Open authenticator status', 'amsec-security-scanner' ),
					'page'  => 'amsec-accounts',
					'hash'  => 'verification',
				),
			},
			'pingbacks' => 'open' === ( $result->evidence['status'] ?? '' ) ? array(
				'label'     => __( 'Turn off pingbacks', 'amsec-security-scanner' ),
				'action'    => 'amsec_approved_setting',
				'nonce'     => 'amsec_approved_setting',
				'operation' => 'close-pingbacks',
			) : null,
			'debug-display' => match ( $result->evidence['fix'] ?? '' ) {
				'plugin' => State::WARN === $result->state ? array(
					'label'     => __( 'Hide error details', 'amsec-security-scanner' ),
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'hide-debug-display',
				) : null,
				'plugin-on' => array(
					'label'     => __( 'Use the wp-config.php display again', 'amsec-security-scanner' ),
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'restore-debug-display',
				),
				default => State::PASS === $result->state ? null : array(
					'label'  => __( 'Open Site Health', 'amsec-security-scanner' ),
					'screen' => 'site-health.php',
				),
			},
			'file-editor' => match ( $result->evidence['fix'] ?? '' ) {
				'plugin' => State::WARN === $result->state ? array(
					'label'     => __( 'Turn off the file editor', 'amsec-security-scanner' ),
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'disable-file-editor',
				) : null,
				'plugin-on' => array(
					'label'     => __( 'Allow the file editor again', 'amsec-security-scanner' ),
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'restore-file-editor',
				),
				default => State::PASS === $result->state ? null : array(
					'label' => __( 'Review the file editor', 'amsec-security-scanner' ),
					'page'  => 'amsec-recovery',
				),
			},
			'captcha-login' => match ( $result->evidence['status'] ?? '' ) {
				'off' => array(
					'label'     => __( 'Turn on the bot trap', 'amsec-security-scanner' ),
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'enable-login-confirm',
				),
				'on' => array(
					'label'     => __( 'Turn off the bot trap', 'amsec-security-scanner' ),
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'disable-login-confirm',
				),
				default => null,
			},
			'compromised-passwords' => match ( $result->evidence['status'] ?? '' ) {
				'off' => array(
					'label'     => __( 'Turn on breached-password checks', 'amsec-security-scanner' ),
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'enable-common-passwords',
				),
				'on' => array(
					'label'     => __( 'Turn off breached-password checks', 'amsec-security-scanner' ),
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'disable-common-passwords',
				),
				default => null,
			},
			'login-hints' => match ( $result->evidence['status'] ?? '' ) {
				'off' => array(
					'label'     => __( 'Use one login message', 'amsec-security-scanner' ),
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'enable-login-hints',
				),
				'on' => array(
					'label'     => __( 'Show separate login messages', 'amsec-security-scanner' ),
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'disable-login-hints',
				),
				default => null,
			},
			'author-archives' => match ( $result->evidence['status'] ?? '' ) {
				'off' => array(
					'label'     => __( 'Hide author pages', 'amsec-security-scanner' ),
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'enable-author-archives',
				),
				'on' => array(
					'label'     => __( 'Show author pages', 'amsec-security-scanner' ),
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'disable-author-archives',
				),
				default => null,
			},
			'rest-user-list' => match ( $result->evidence['status'] ?? '' ) {
				'off' => array(
					'label'     => __( 'Require login for the user list', 'amsec-security-scanner' ),
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'enable-rest-users',
				),
				'on' => array(
					'label'     => __( 'Allow the public user list', 'amsec-security-scanner' ),
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'disable-rest-users',
				),
				default => null,
			},
			'version-tag' => match ( $result->evidence['status'] ?? '' ) {
				'off' => array(
					'label'     => __( 'Hide the version tag', 'amsec-security-scanner' ),
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'enable-version-tag',
				),
				'on' => array(
					'label'     => __( 'Show the version tag', 'amsec-security-scanner' ),
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'disable-version-tag',
				),
				default => null,
			},
			'discovery-links' => match ( $result->evidence['status'] ?? '' ) {
				'off' => array(
					'label'     => __( 'Remove discovery links', 'amsec-security-scanner' ),
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'enable-discovery-links',
				),
				'on' => array(
					'label'     => __( 'Show discovery links', 'amsec-security-scanner' ),
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'disable-discovery-links',
				),
				default => null,
			},
			'xmlrpc-auth' => 'open' === ( $result->evidence['auth'] ?? '' ) || State::PASS !== $result->state ? array(
				'label' => __( 'Open login protection', 'amsec-security-scanner' ),
				'page'  => 'amsec-accounts',
				'hash'  => 'sign-in',
			) : null,
			'uploads-php-execution' => array(
				'label' => __( 'Review PHP in uploads', 'amsec-security-scanner' ),
				'page'  => 'amsec-uploads',
			),
			'uploads-php-files' => State::PASS === $result->state ? null : array(
				'label'  => __( 'Review uploads', 'amsec-security-scanner' ),
				'screen' => 'upload.php',
			),
			'readme-file', 'license-file', 'debug-log', 'sample-config', 'error-log', 'config-backup', 'root-exposure', 'filesystem-permissions' => State::PASS === $result->state ? null : array(
				'label' => __( 'Review this finding', 'amsec-security-scanner' ),
				'page'  => 'amsec-exposure',
			),
			'php-version' => State::PASS === $result->state ? null : array(
				'label'  => __( 'Open Site Health', 'amsec-security-scanner' ),
				'screen' => 'site-health.php',
			),
			'background-updates' => State::PASS === $result->state ? null : array(
				'label'  => __( 'Review updates', 'amsec-security-scanner' ),
				'screen' => 'update-core.php',
			),
			'daily-checks', 'daily-file-checks' => State::PASS === $result->state ? null : array(
				'label' => __( 'Review the schedule', 'amsec-security-scanner' ),
				'page'  => 'amsec-schedule',
				'hash'  => 'amsec-schedule',
			),
			'local-code' => State::PASS === $result->state ? null : array(
				'label' => __( 'Review malware findings', 'amsec-security-scanner' ),
				'page'  => 'amsec-file-checks',
				'hash'  => 'amsec-malware',
			),
			'file-modes' => in_array( $result->state, array( State::WARN, State::UNKNOWN ), true ) ? array(
				'label' => __( 'Review file modes', 'amsec-security-scanner' ),
				'page'  => 'amsec-recovery',
			) : null,
			'bot-controls' => in_array( $result->evidence['mode'] ?? '', array( 'off', 'observe' ), true ) ? array(
				'label' => __( 'Review bot controls', 'amsec-security-scanner' ),
				'page'  => 'amsec-bots',
			) : null,
			'rest-rates' => in_array( $result->evidence['mode'] ?? '', array( 'off', 'observe' ), true ) ? array(
				'label' => __( 'Review REST limits', 'amsec-security-scanner' ),
				'page'  => 'amsec-rest-rates',
			) : null,
			'rest-request-watch' => 'disabled' === ( $result->evidence['status'] ?? '' ) ? array(
				'label' => __( 'Open Traffic', 'amsec-security-scanner' ),
				'page'  => 'amsec-traffic',
			) : null,
			'finding-emails' => 'off' === ( $result->evidence['status'] ?? '' ) ? array(
				'label' => __( 'Open notification settings', 'amsec-security-scanner' ),
				'page'  => 'amsec-settings',
				'hash'  => 'amsec-alerts',
			) : null,
			'weekly-digest' => 'off' === ( $result->evidence['status'] ?? '' ) ? array(
				'label' => __( 'Review weekly digest', 'amsec-security-scanner' ),
				'page'  => 'amsec-digest',
			) : null,
			'traffic-history' => 'off' === ( $result->evidence['status'] ?? '' ) ? array(
				'label' => __( 'Review traffic history', 'amsec-security-scanner' ),
				'page'  => 'amsec-traffic',
			) : null,
			'network-controls' => in_array( $result->evidence['status'] ?? '', array( 'observe', 'block' ), true ) ? array(
				'label' => __( 'Review network controls', 'amsec-security-scanner' ),
				'page'  => 'amsec-network',
			) : null,
			'trusted-proxies' => in_array( $result->evidence['status'] ?? '', array( 'xff', 'single' ), true ) ? array(
				'label' => __( 'Review trusted proxies', 'amsec-security-scanner' ),
				'page'  => 'amsec-proxies',
			) : null,
			'security-activity' => 'off' === ( $result->evidence['status'] ?? '' ) ? array(
				'label' => __( 'Review security activity', 'amsec-security-scanner' ),
				'page'  => 'amsec-activity',
			) : null,
			'account-sessions' => 'extra' === ( $result->evidence['status'] ?? '' ) ? array(
				'label' => __( 'Review sessions', 'amsec-security-scanner' ),
				'page'  => 'amsec-sessions',
			) : null,
			'rule-review' => in_array( $result->evidence['status'] ?? '', array( 'overdue', 'unknown' ), true ) ? array(
				'label' => __( 'Review rule information', 'amsec-security-scanner' ),
				'page'  => 'amsec-rules',
			) : null,
			'code-baselines' => in_array( $result->evidence['status'] ?? '', array( 'none', 'preview' ), true ) ? array(
				'label' => __( 'Review code baselines', 'amsec-security-scanner' ),
				'page'  => 'amsec-baselines',
			) : null,
			'ai-readers' => State::WARN === $result->state ? array(
				'label'  => 'open' === ( $result->evidence['guest_comments'] ?? '' ) ? __( 'Discussion settings', 'amsec-security-scanner' ) : __( 'General settings', 'amsec-security-scanner' ),
				'screen' => 'open' === ( $result->evidence['guest_comments'] ?? '' ) ? 'options-discussion.php' : 'options-general.php',
			) : null,
			'ai-readiness' => match ( true ) {
				'on' === ( $result->evidence['assistant'] ?? '' ) => array(
					'label' => __( 'Review AI assistant access', 'amsec-security-scanner' ),
					'page'  => 'amsec-assistant',
					'hash'  => 'amsec-mcp',
				),
				'open' === ( $result->evidence['app_passwords'] ?? '' ) => array(
					'label'     => __( 'Pause application passwords', 'amsec-security-scanner' ),
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'disable-application-passwords',
				),
				'plugin-off' === ( $result->evidence['app_passwords'] ?? '' ) => array(
					'label'     => __( 'Allow application passwords again', 'amsec-security-scanner' ),
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'enable-application-passwords',
				),
				default => null,
			},
			'known-holes' => match ( true ) {
				'no' === $enabled => array(
					'label'  => __( 'Enable vulnerability checks', 'amsec-security-scanner' ),
					'action' => 'amsec_security_scanner_vulnerability_enable',
					'nonce'  => 'amsec_security_scanner_vulnerability_enable',
				),
				'none' === $stored => array(
					'label'  => __( 'Check installed versions', 'amsec-security-scanner' ),
					'action' => 'amsec_security_scanner_vulnerability_scan',
					'nonce'  => 'amsec_security_scanner_vulnerability_scan',
				),
				'found' === $stored => array(
					'label' => __( 'Review vulnerability checks', 'amsec-security-scanner' ),
					'page'  => 'amsec-vulnerabilities',
					'hash'  => 'amsec-vulnerabilities',
				),
				default => null,
			},
			'release-files' => match ( $stored ) {
				'none' => array(
					'label'  => __( 'Run integrity scan', 'amsec-security-scanner' ),
					'action' => 'amsec_security_scanner_integrity_start',
					'nonce'  => 'amsec_security_scanner_integrity_start',
				),
				'partial' => array(
					'label'  => __( 'Continue integrity scan', 'amsec-security-scanner' ),
					'action' => 'amsec_security_scanner_integrity_resume',
					'nonce'  => 'amsec_security_scanner_integrity_resume',
					'scan'   => 'integrity',
				),
				'found' => array(
					'label' => __( 'Review integrity scan', 'amsec-security-scanner' ),
					'page'  => 'amsec-file-checks',
					'hash'  => 'amsec-integrity',
				),
				default => null,
			},
			'public-content' => match ( $stored ) {
				'none' => array(
					'label'     => __( 'Scan published content', 'amsec-security-scanner' ),
					'action'    => 'amsec_content_scan',
					'nonce'     => 'amsec_content_start',
					'operation' => 'start',
				),
				'partial' => array(
					'label'     => __( 'Continue scan', 'amsec-security-scanner' ),
					'action'    => 'amsec_content_scan',
					'nonce'     => 'amsec_content_resume',
					'operation' => 'resume',
					'scan'      => 'content',
				),
				'found' => array(
					'label' => __( 'Review content scan', 'amsec-security-scanner' ),
					'page'  => 'amsec-content',
				),
				default => null,
			},
			'suspicious-files' => match ( $stored ) {
				'none' => array(
					'label'  => __( 'Run file scan', 'amsec-security-scanner' ),
					'action' => 'amsec_security_scanner_file_scan_start',
					'nonce'  => 'amsec_security_scanner_file_scan_start',
				),
				'partial' => array(
					'label'  => __( 'Continue file scan', 'amsec-security-scanner' ),
					'action' => 'amsec_security_scanner_file_scan_resume',
					'nonce'  => 'amsec_security_scanner_file_scan_resume',
					'scan'   => 'files',
				),
				'found' => array(
					'label' => __( 'Review suspicious files', 'amsec-security-scanner' ),
					'page'  => 'amsec-file-checks',
					'hash'  => 'amsec-file-scan',
				),
				default => null,
			},
			'closed-plugins' => in_array( $stored, array( 'none', 'partial', 'found', 'unknown' ), true ) ? array(
				'label' => __( 'Review directory status', 'amsec-security-scanner' ),
				'page'  => 'amsec-repository',
			) : null,
			'local-inventory' => in_array( $stored, array( 'none', 'partial', 'found', 'unknown' ), true ) ? array(
				'label' => __( 'Review local inventory', 'amsec-security-scanner' ),
				'page'  => 'amsec-exposure',
			) : null,
			'security-headers' => in_array( $stored, array( 'none', 'partial', 'found', 'unknown' ), true ) ? array(
				'label' => __( 'Review security headers', 'amsec-security-scanner' ),
				'page'  => 'amsec-headers',
			) : null,
			default => null,
		};
	}
}
