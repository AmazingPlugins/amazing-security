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
			'https-admin' => __( 'HTTPS', 'amazing-security-scanner' ),
			'core-updates' => __( 'WordPress updates', 'amazing-security-scanner' ),
			'default-admin-login' => __( 'Admin login', 'amazing-security-scanner' ),
			'debug-display' => __( 'Debug display', 'amazing-security-scanner' ),
			'file-editor' => __( 'Theme and plugin editor', 'amazing-security-scanner' ),
			'login-rate-mode' => __( 'Login monitoring', 'amazing-security-scanner' ),
			'uploads-php-execution' => __( 'PHP in uploads', 'amazing-security-scanner' ),
			'uploads-php-files' => __( 'PHP files in uploads', 'amazing-security-scanner' ),
			'file-modes' => __( 'File modes', 'amazing-security-scanner' ),
			'filesystem-permissions' => __( 'File permissions', 'amazing-security-scanner' ),
			'pingbacks' => __( 'Pingbacks', 'amazing-security-scanner' ),
			'xmlrpc-auth' => __( 'XML-RPC sign-in', 'amazing-security-scanner' ),
			'captcha-login' => __( 'Login bot trap', 'amazing-security-scanner' ),
			'compromised-passwords' => __( 'Compromised passwords', 'amazing-security-scanner' ),
			'login-hints' => __( 'Login messages', 'amazing-security-scanner' ),
			'author-archives' => __( 'Author pages', 'amazing-security-scanner' ),
			'rest-user-list' => __( 'REST user list', 'amazing-security-scanner' ),
			'version-tag' => __( 'Version tag', 'amazing-security-scanner' ),
			'discovery-links' => __( 'Discovery links', 'amazing-security-scanner' ),
			'readme-file' => __( 'Readme file', 'amazing-security-scanner' ),
			'license-file' => __( 'License file', 'amazing-security-scanner' ),
			'debug-log' => __( 'Debug log', 'amazing-security-scanner' ),
			'sample-config' => __( 'Sample config', 'amazing-security-scanner' ),
			'error-log' => __( 'Error log', 'amazing-security-scanner' ),
			'config-backup' => __( 'Config backup', 'amazing-security-scanner' ),
			'php-version' => __( 'PHP version', 'amazing-security-scanner' ),
			'background-updates' => __( 'Background updates', 'amazing-security-scanner' ),
			'plugin-updates' => __( 'Plugin updates', 'amazing-security-scanner' ),
			'theme-updates' => __( 'Theme updates', 'amazing-security-scanner' ),
			'inactive-plugins' => __( 'Inactive plugins', 'amazing-security-scanner' ),
			'inactive-themes' => __( 'Inactive themes', 'amazing-security-scanner' ),
			'root-exposure' => __( 'Root files', 'amazing-security-scanner' ),
			'bot-controls' => __( 'Bot controls', 'amazing-security-scanner' ),
			'rest-rates' => __( 'REST limits', 'amazing-security-scanner' ),
			'rest-request-watch' => __( 'REST request watch', 'amazing-security-scanner' ),
			'finding-emails' => __( 'Finding emails', 'amazing-security-scanner' ),
			'weekly-digest' => __( 'Weekly digest', 'amazing-security-scanner' ),
			'traffic-history' => __( 'Traffic history', 'amazing-security-scanner' ),
			'network-controls' => __( 'Network controls', 'amazing-security-scanner' ),
			'trusted-proxies' => __( 'Trusted proxies', 'amazing-security-scanner' ),
			'security-activity' => __( 'Security activity', 'amazing-security-scanner' ),
			'account-sessions' => __( 'Account sessions', 'amazing-security-scanner' ),
			'code-baselines' => __( 'Code baselines', 'amazing-security-scanner' ),
			'daily-checks' => __( 'Daily checks', 'amazing-security-scanner' ),
			'daily-file-checks' => __( 'Daily file checks', 'amazing-security-scanner' ),
			'rule-review' => __( 'Rule review', 'amazing-security-scanner' ),
			'ai-readers' => __( 'Bots and AI readers', 'amazing-security-scanner' ),
			'ai-readiness' => __( 'AI security and readiness', 'amazing-security-scanner' ),
			'known-holes' => __( 'Known holes', 'amazing-security-scanner' ),
			'release-files' => __( 'Release files', 'amazing-security-scanner' ),
			'closed-plugins' => __( 'Closed plugins', 'amazing-security-scanner' ),
			'public-content' => __( 'Posts and comments', 'amazing-security-scanner' ),
			'local-code' => __( 'Malware scan', 'amazing-security-scanner' ),
			'authenticator-app' => __( 'Authenticator app', 'amazing-security-scanner' ),
			'passkeys-status' => __( 'Passkeys', 'amazing-security-scanner' ),
			'suspicious-files' => __( 'Suspicious files', 'amazing-security-scanner' ),
			'local-inventory' => __( 'Local inventory', 'amazing-security-scanner' ),
			'security-headers' => __( 'Security headers', 'amazing-security-scanner' ),
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
				'label'  => __( 'Review plugins', 'amazing-security-scanner' ),
				'screen' => 'plugins.php',
			) : null,
			'inactive-themes' => State::WARN === $result->state ? array(
				'label'  => __( 'Review themes', 'amazing-security-scanner' ),
				'screen' => 'themes.php',
			) : null,
			'https-admin' => State::PASS === $result->state ? null : array(
				'label'  => __( 'Open Site Health', 'amazing-security-scanner' ),
				'screen' => 'site-health.php',
			),
			'core-updates', 'plugin-updates', 'theme-updates' => in_array( $result->state, array( State::WARN, State::UNKNOWN ), true ) ? array(
				'label'  => __( 'Review updates', 'amazing-security-scanner' ),
				'screen' => 'update-core.php',
			) : null,
			'default-admin-login' => State::WARN === $result->state ? array(
				'label'  => __( 'Review administrators', 'amazing-security-scanner' ),
				'screen' => 'users.php',
			) : null,
			'login-rate-mode' => State::PASS === $result->state ? null : array(
				'label' => __( 'Open login protection', 'amazing-security-scanner' ),
				'page'  => 'amsec-accounts',
				'hash'  => 'sign-in',
			),
			'authenticator-app', 'passkeys-status' => match ( true ) {
				State::PASS === $result->state => null,
				'missing' === $status => array(
					'label'   => RequiredTotpPage::installed( 'two-factor' ) && current_user_can( 'activate_plugins' ) ? __( 'Activate Two Factor', 'amazing-security-scanner' ) : __( 'Find Two Factor', 'amazing-security-scanner' ),
					'install' => 'two-factor',
				),
				'passkeys-status' === $result->checkId => array(
					'label' => __( 'Open passkey status', 'amazing-security-scanner' ),
					'page'  => 'amsec-accounts',
					'hash'  => 'passkeys',
				),
				default => array(
					'label' => __( 'Open authenticator status', 'amazing-security-scanner' ),
					'page'  => 'amsec-accounts',
					'hash'  => 'verification',
				),
			},
			'pingbacks' => 'open' === ( $result->evidence['status'] ?? '' ) ? array(
				'label'     => __( 'Turn off pingbacks', 'amazing-security-scanner' ),
				'action'    => 'amsec_approved_setting',
				'nonce'     => 'amsec_approved_setting',
				'operation' => 'close-pingbacks',
			) : null,
			'debug-display' => match ( $result->evidence['fix'] ?? '' ) {
				'plugin' => State::WARN === $result->state ? array(
					'label'     => __( 'Hide error details', 'amazing-security-scanner' ),
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'hide-debug-display',
				) : null,
				'plugin-on' => array(
					'label'     => __( 'Use the wp-config.php display again', 'amazing-security-scanner' ),
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'restore-debug-display',
				),
				default => State::PASS === $result->state ? null : array(
					'label'  => __( 'Open Site Health', 'amazing-security-scanner' ),
					'screen' => 'site-health.php',
				),
			},
			'file-editor' => match ( $result->evidence['fix'] ?? '' ) {
				'plugin' => State::WARN === $result->state ? array(
					'label'     => __( 'Turn off the file editor', 'amazing-security-scanner' ),
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'disable-file-editor',
				) : null,
				'plugin-on' => array(
					'label'     => __( 'Allow the file editor again', 'amazing-security-scanner' ),
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'restore-file-editor',
				),
				default => State::PASS === $result->state ? null : array(
					'label' => __( 'Review the file editor', 'amazing-security-scanner' ),
					'page'  => 'amsec-recovery',
				),
			},
			'captcha-login' => match ( $result->evidence['status'] ?? '' ) {
				'off' => array(
					'label'     => __( 'Turn on the bot trap', 'amazing-security-scanner' ),
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'enable-login-confirm',
				),
				'on' => array(
					'label'     => __( 'Turn off the bot trap', 'amazing-security-scanner' ),
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'disable-login-confirm',
				),
				default => null,
			},
			'compromised-passwords' => match ( $result->evidence['status'] ?? '' ) {
				'off' => array(
					'label'     => __( 'Turn on breached-password checks', 'amazing-security-scanner' ),
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'enable-common-passwords',
				),
				'on' => array(
					'label'     => __( 'Turn off breached-password checks', 'amazing-security-scanner' ),
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'disable-common-passwords',
				),
				default => null,
			},
			'login-hints' => match ( $result->evidence['status'] ?? '' ) {
				'off' => array(
					'label'     => __( 'Use one login message', 'amazing-security-scanner' ),
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'enable-login-hints',
				),
				'on' => array(
					'label'     => __( 'Show separate login messages', 'amazing-security-scanner' ),
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'disable-login-hints',
				),
				default => null,
			},
			'author-archives' => match ( $result->evidence['status'] ?? '' ) {
				'off' => array(
					'label'     => __( 'Hide author pages', 'amazing-security-scanner' ),
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'enable-author-archives',
				),
				'on' => array(
					'label'     => __( 'Show author pages', 'amazing-security-scanner' ),
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'disable-author-archives',
				),
				default => null,
			},
			'rest-user-list' => match ( $result->evidence['status'] ?? '' ) {
				'off' => array(
					'label'     => __( 'Require login for the user list', 'amazing-security-scanner' ),
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'enable-rest-users',
				),
				'on' => array(
					'label'     => __( 'Allow the public user list', 'amazing-security-scanner' ),
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'disable-rest-users',
				),
				default => null,
			},
			'version-tag' => match ( $result->evidence['status'] ?? '' ) {
				'off' => array(
					'label'     => __( 'Hide the version tag', 'amazing-security-scanner' ),
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'enable-version-tag',
				),
				'on' => array(
					'label'     => __( 'Show the version tag', 'amazing-security-scanner' ),
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'disable-version-tag',
				),
				default => null,
			},
			'discovery-links' => match ( $result->evidence['status'] ?? '' ) {
				'off' => array(
					'label'     => __( 'Remove discovery links', 'amazing-security-scanner' ),
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'enable-discovery-links',
				),
				'on' => array(
					'label'     => __( 'Show discovery links', 'amazing-security-scanner' ),
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'disable-discovery-links',
				),
				default => null,
			},
			'xmlrpc-auth' => 'open' === ( $result->evidence['auth'] ?? '' ) || State::PASS !== $result->state ? array(
				'label' => __( 'Open login protection', 'amazing-security-scanner' ),
				'page'  => 'amsec-accounts',
				'hash'  => 'sign-in',
			) : null,
			'uploads-php-execution' => array(
				'label' => __( 'Review PHP in uploads', 'amazing-security-scanner' ),
				'page'  => 'amsec-uploads',
			),
			'uploads-php-files' => State::PASS === $result->state ? null : array(
				'label'  => __( 'Review uploads', 'amazing-security-scanner' ),
				'screen' => 'upload.php',
			),
			'readme-file', 'license-file', 'debug-log', 'sample-config', 'error-log', 'config-backup', 'root-exposure', 'filesystem-permissions' => State::PASS === $result->state ? null : array(
				'label' => __( 'Review this finding', 'amazing-security-scanner' ),
				'page'  => 'amsec-exposure',
			),
			'php-version' => State::PASS === $result->state ? null : array(
				'label'  => __( 'Open Site Health', 'amazing-security-scanner' ),
				'screen' => 'site-health.php',
			),
			'background-updates' => State::PASS === $result->state ? null : array(
				'label'  => __( 'Review updates', 'amazing-security-scanner' ),
				'screen' => 'update-core.php',
			),
			'daily-checks', 'daily-file-checks' => State::PASS === $result->state ? null : array(
				'label' => __( 'Review the schedule', 'amazing-security-scanner' ),
				'page'  => 'amsec-schedule',
				'hash'  => 'amsec-schedule',
			),
			'local-code' => State::PASS === $result->state ? null : array(
				'label' => __( 'Review malware findings', 'amazing-security-scanner' ),
				'page'  => 'amsec-file-checks',
				'hash'  => 'amsec-malware',
			),
			'file-modes' => in_array( $result->state, array( State::WARN, State::UNKNOWN ), true ) ? array(
				'label' => __( 'Review file modes', 'amazing-security-scanner' ),
				'page'  => 'amsec-recovery',
			) : null,
			'bot-controls' => in_array( $result->evidence['mode'] ?? '', array( 'off', 'observe' ), true ) ? array(
				'label' => __( 'Review bot controls', 'amazing-security-scanner' ),
				'page'  => 'amsec-bots',
			) : null,
			'rest-rates' => in_array( $result->evidence['mode'] ?? '', array( 'off', 'observe' ), true ) ? array(
				'label' => __( 'Review REST limits', 'amazing-security-scanner' ),
				'page'  => 'amsec-rest-rates',
			) : null,
			'rest-request-watch' => 'disabled' === ( $result->evidence['status'] ?? '' ) ? array(
				'label' => __( 'Open Traffic', 'amazing-security-scanner' ),
				'page'  => 'amsec-traffic',
			) : null,
			'finding-emails' => 'off' === ( $result->evidence['status'] ?? '' ) ? array(
				'label' => __( 'Open notification settings', 'amazing-security-scanner' ),
				'page'  => 'amsec-settings',
				'hash'  => 'amsec-alerts',
			) : null,
			'weekly-digest' => 'off' === ( $result->evidence['status'] ?? '' ) ? array(
				'label' => __( 'Review weekly digest', 'amazing-security-scanner' ),
				'page'  => 'amsec-digest',
			) : null,
			'traffic-history' => 'off' === ( $result->evidence['status'] ?? '' ) ? array(
				'label' => __( 'Review traffic history', 'amazing-security-scanner' ),
				'page'  => 'amsec-traffic',
			) : null,
			'network-controls' => in_array( $result->evidence['status'] ?? '', array( 'observe', 'block' ), true ) ? array(
				'label' => __( 'Review network controls', 'amazing-security-scanner' ),
				'page'  => 'amsec-network',
			) : null,
			'trusted-proxies' => in_array( $result->evidence['status'] ?? '', array( 'xff', 'single' ), true ) ? array(
				'label' => __( 'Review trusted proxies', 'amazing-security-scanner' ),
				'page'  => 'amsec-proxies',
			) : null,
			'security-activity' => 'off' === ( $result->evidence['status'] ?? '' ) ? array(
				'label' => __( 'Review security activity', 'amazing-security-scanner' ),
				'page'  => 'amsec-activity',
			) : null,
			'account-sessions' => 'extra' === ( $result->evidence['status'] ?? '' ) ? array(
				'label' => __( 'Review sessions', 'amazing-security-scanner' ),
				'page'  => 'amsec-sessions',
			) : null,
			'rule-review' => in_array( $result->evidence['status'] ?? '', array( 'overdue', 'unknown' ), true ) ? array(
				'label' => __( 'Review rule information', 'amazing-security-scanner' ),
				'page'  => 'amsec-rules',
			) : null,
			'code-baselines' => in_array( $result->evidence['status'] ?? '', array( 'none', 'preview' ), true ) ? array(
				'label' => __( 'Review code baselines', 'amazing-security-scanner' ),
				'page'  => 'amsec-baselines',
			) : null,
			'ai-readers' => State::WARN === $result->state ? array(
				'label'  => 'open' === ( $result->evidence['guest_comments'] ?? '' ) ? __( 'Discussion settings', 'amazing-security-scanner' ) : __( 'General settings', 'amazing-security-scanner' ),
				'screen' => 'open' === ( $result->evidence['guest_comments'] ?? '' ) ? 'options-discussion.php' : 'options-general.php',
			) : null,
			'ai-readiness' => match ( true ) {
				'on' === ( $result->evidence['assistant'] ?? '' ) => array(
					'label' => __( 'Review AI assistant access', 'amazing-security-scanner' ),
					'page'  => 'amsec-assistant',
					'hash'  => 'amsec-mcp',
				),
				'open' === ( $result->evidence['app_passwords'] ?? '' ) => array(
					'label'     => __( 'Pause application passwords', 'amazing-security-scanner' ),
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'disable-application-passwords',
				),
				'plugin-off' === ( $result->evidence['app_passwords'] ?? '' ) => array(
					'label'     => __( 'Allow application passwords again', 'amazing-security-scanner' ),
					'action'    => 'amsec_approved_setting',
					'nonce'     => 'amsec_approved_setting',
					'operation' => 'enable-application-passwords',
				),
				default => null,
			},
			'known-holes' => match ( true ) {
				'no' === $enabled => array(
					'label'  => __( 'Enable vulnerability checks', 'amazing-security-scanner' ),
					'action' => 'amazing_security_vulnerability_enable',
					'nonce'  => 'amazing_security_vulnerability_enable',
				),
				'none' === $stored => array(
					'label'  => __( 'Check installed versions', 'amazing-security-scanner' ),
					'action' => 'amazing_security_vulnerability_scan',
					'nonce'  => 'amazing_security_vulnerability_scan',
				),
				'found' === $stored => array(
					'label' => __( 'Review vulnerability checks', 'amazing-security-scanner' ),
					'page'  => 'amsec-vulnerabilities',
					'hash'  => 'amsec-vulnerabilities',
				),
				default => null,
			},
			'release-files' => match ( $stored ) {
				'none' => array(
					'label'  => __( 'Run integrity scan', 'amazing-security-scanner' ),
					'action' => 'amazing_security_integrity_start',
					'nonce'  => 'amazing_security_integrity_start',
				),
				'partial' => array(
					'label'  => __( 'Continue integrity scan', 'amazing-security-scanner' ),
					'action' => 'amazing_security_integrity_resume',
					'nonce'  => 'amazing_security_integrity_resume',
					'scan'   => 'integrity',
				),
				'found' => array(
					'label' => __( 'Review integrity scan', 'amazing-security-scanner' ),
					'page'  => 'amsec-file-checks',
					'hash'  => 'amsec-integrity',
				),
				default => null,
			},
			'public-content' => match ( $stored ) {
				'none' => array(
					'label'     => __( 'Scan published content', 'amazing-security-scanner' ),
					'action'    => 'amsec_content_scan',
					'nonce'     => 'amsec_content_start',
					'operation' => 'start',
				),
				'partial' => array(
					'label'     => __( 'Continue scan', 'amazing-security-scanner' ),
					'action'    => 'amsec_content_scan',
					'nonce'     => 'amsec_content_resume',
					'operation' => 'resume',
					'scan'      => 'content',
				),
				'found' => array(
					'label' => __( 'Review content scan', 'amazing-security-scanner' ),
					'page'  => 'amsec-content',
				),
				default => null,
			},
			'suspicious-files' => match ( $stored ) {
				'none' => array(
					'label'  => __( 'Run file scan', 'amazing-security-scanner' ),
					'action' => 'amazing_security_file_scan_start',
					'nonce'  => 'amazing_security_file_scan_start',
				),
				'partial' => array(
					'label'  => __( 'Continue file scan', 'amazing-security-scanner' ),
					'action' => 'amazing_security_file_scan_resume',
					'nonce'  => 'amazing_security_file_scan_resume',
					'scan'   => 'files',
				),
				'found' => array(
					'label' => __( 'Review suspicious files', 'amazing-security-scanner' ),
					'page'  => 'amsec-file-checks',
					'hash'  => 'amsec-file-scan',
				),
				default => null,
			},
			'closed-plugins' => in_array( $stored, array( 'none', 'partial', 'found', 'unknown' ), true ) ? array(
				'label' => __( 'Review directory status', 'amazing-security-scanner' ),
				'page'  => 'amsec-repository',
			) : null,
			'local-inventory' => in_array( $stored, array( 'none', 'partial', 'found', 'unknown' ), true ) ? array(
				'label' => __( 'Review local inventory', 'amazing-security-scanner' ),
				'page'  => 'amsec-exposure',
			) : null,
			'security-headers' => in_array( $stored, array( 'none', 'partial', 'found', 'unknown' ), true ) ? array(
				'label' => __( 'Review security headers', 'amazing-security-scanner' ),
				'page'  => 'amsec-headers',
			) : null,
			default => null,
		};
	}
}
