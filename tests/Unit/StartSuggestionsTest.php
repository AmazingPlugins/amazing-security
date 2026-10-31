<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit;

use AmazingPlugins\Security\Admin\StartHere;
use AmazingPlugins\Security\Checks\AiReadersCheck;
use AmazingPlugins\Security\Checks\AiReadinessCheck;
use AmazingPlugins\Security\Checks\BotModeCheck;
use AmazingPlugins\Security\Checks\FileModesCheck;
use AmazingPlugins\Security\Checks\RestRateCheck;
use AmazingPlugins\Security\Checks\SiteWatchCheck;
use AmazingPlugins\Security\Checks\FollowUpCheck;
use AmazingPlugins\Security\Checks\KnownHolesCheck;
use AmazingPlugins\Security\Checks\PingbackCheck;
use AmazingPlugins\Security\Checks\XmlRpcAuthCheck;
use AmazingPlugins\Security\Checks\UploadsExecutionCheck;
use AmazingPlugins\Security\Findings\CheckResult;
use AmazingPlugins\Security\Scan\ScanContext;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

final class StartSuggestionsTest extends TestCase {
	public function test_start_here_keeps_the_fixed_order_and_leaves_later_suggestions_after(): void {
		$results = array();
		foreach ( array( 'security-headers', 'local-inventory', 'local-code', 'suspicious-files', 'public-content', 'closed-plugins', 'release-files', 'known-holes', 'ai-readiness', 'ai-readers', 'rule-review', 'daily-file-checks', 'daily-checks', 'code-baselines', 'account-sessions', 'security-activity', 'trusted-proxies', 'network-controls', 'traffic-history', 'weekly-digest', 'finding-emails', 'rest-request-watch', 'rest-rates', 'bot-controls', 'uploads-php-files', 'inactive-themes', 'root-exposure', 'inactive-plugins', 'theme-updates', 'plugin-updates', 'background-updates', 'php-version', 'config-backup', 'error-log', 'sample-config', 'debug-log', 'license-file', 'readme-file', 'discovery-links', 'version-tag', 'rest-user-list', 'author-archives', 'login-hints', 'compromised-passwords', 'captcha-login', 'xmlrpc-auth', 'pingbacks', 'file-modes', 'login-rate-mode', 'https-admin', 'uploads-php-execution', 'file-editor' ) as $id ) {
			$results[] = new CheckResult( $id, 'warn', $id . ' next step', 'https://developer.wordpress.org/advanced-administration/security/hardening/', new DateTimeImmutable( '2026-10-01T00:00:00Z' ), 'low', 'complete', array() );
		}
		self::assertSame( array( 'https-admin', 'file-editor', 'login-rate-mode' ), array_map( static fn( CheckResult $row ): string => $row->checkId, StartHere::rows( $results, StartHere::ORDER ) ) );
		self::assertSame( array( 'uploads-php-execution', 'uploads-php-files', 'file-modes', 'pingbacks', 'xmlrpc-auth', 'captcha-login', 'compromised-passwords', 'login-hints', 'author-archives', 'rest-user-list', 'version-tag', 'discovery-links', 'readme-file', 'license-file', 'debug-log', 'sample-config', 'error-log', 'config-backup', 'php-version', 'background-updates', 'plugin-updates', 'theme-updates', 'inactive-plugins', 'inactive-themes', 'root-exposure', 'bot-controls', 'rest-rates', 'rest-request-watch', 'finding-emails', 'weekly-digest', 'traffic-history', 'network-controls', 'trusted-proxies', 'security-activity', 'account-sessions', 'code-baselines', 'daily-checks', 'daily-file-checks', 'rule-review', 'ai-readers', 'ai-readiness', 'known-holes', 'release-files', 'closed-plugins', 'public-content', 'local-code', 'suspicious-files', 'local-inventory', 'security-headers' ), array_map( static fn( CheckResult $row ): string => $row->checkId, StartHere::rows( $results, StartHere::LATER ) ) );
	}

	public function test_pingbacks_warn_only_when_open_and_do_not_describe_a_change(): void {
		$open    = ( new PingbackCheck( static fn(): string => 'open' ) )->run( new ScanContext() )[0];
		$closed  = ( new PingbackCheck( static fn(): string => 'closed' ) )->run( new ScanContext() )[0];
		$missing = ( new PingbackCheck( static fn(): bool => false ) )->run( new ScanContext() )[0];
		self::assertSame( 'warn', $open->state );
		self::assertStringContainsString( 'leaves the setting as it is', $open->summary );
		self::assertStringContainsString( 'XML-RPC is unchanged', $open->summary );
		self::assertSame( 'pass', $closed->state );
		self::assertSame( 'unknown', $missing->state );
	}

	public function test_xmlrpc_sign_in_warns_when_allowed_and_does_not_turn_it_off(): void {
		$open   = ( new XmlRpcAuthCheck( static fn(): mixed => null ) )->run( new ScanContext() )[0];
		$closed = ( new XmlRpcAuthCheck( static fn(): string => '1' ) )->run( new ScanContext() )[0];
		$unread = ( new XmlRpcAuthCheck( static fn(): string => 'yes' ) )->run( new ScanContext() )[0];

		self::assertSame( 'warn', $open->state );
		self::assertSame( 'open', $open->evidence['auth'] );
		self::assertStringContainsString( 'still allowed', $open->summary );
		self::assertStringContainsString( 'does not turn that off', $open->summary );
		self::assertStringNotContainsString( 'safe', $open->summary );
		self::assertSame( 'amsec-accounts', StartHere::control( $open )['page'] );
		self::assertSame( 'sign-in', StartHere::control( $open )['hash'] );

		self::assertSame( 'pass', $closed->state );
		self::assertStringContainsString( 'turned off', $closed->summary );
		self::assertStringContainsString( 'Pingbacks stay a separate setting', $closed->summary );
		self::assertNull( StartHere::control( $closed ) );

		self::assertSame( 'unknown', $unread->state );
		self::assertStringContainsString( 'could not be read', $unread->summary );
	}

	public function test_uploads_rule_names_the_rule_without_a_probe(): void {
		$seen   = ( new UploadsExecutionCheck( static fn(): string => 'engine-off' ) )->run( new ScanContext() )[0];
		$absent = ( new UploadsExecutionCheck( static fn(): string => '' ) )->run( new ScanContext() )[0];
		self::assertSame( 'unknown', $seen->state );
		self::assertSame( 'partial', $seen->coverage );
		self::assertSame( 'local_rule', $seen->evidence['method'] );
		self::assertStringContainsString( 'engine-off', $seen->summary );
		self::assertStringContainsString( 'No test file was written.', $seen->summary );
		self::assertSame( 'warn', $absent->state );
		self::assertSame( 'no_runtime_probe', $absent->evidence['method'] );
		self::assertSame( 'engine-off', UploadsExecutionCheck::classify( "php_flag engine off\n" ) );
		self::assertSame( 'user-ini-engine-off', UploadsExecutionCheck::classify( "engine = Off\n" ) );
		self::assertSame( 'user-ini-engine-off', UploadsExecutionCheck::classify( "php_admin_value[engine] = Off\n" ) );
		self::assertSame( 'filesmatch-deny', UploadsExecutionCheck::classify( "<FilesMatch \\.php>\nRequire all denied\n</FilesMatch>" ) );
		self::assertSame( '', UploadsExecutionCheck::classify( 'Options -Indexes' ) );
		self::assertSame( '', UploadsExecutionCheck::classify( "engine = On\n" ) );
	}

	public function test_ai_readers_warn_for_open_bots_and_only_describe_crawler_rules(): void {
		$open    = ( new AiReadersCheck(
			static fn(): array => array(
				'guest_comments' => 'open',
				'registration'   => 'open',
				'robots'         => "User-agent: *\nDisallow: /wp-admin/\n",
			)
		) )->run( new ScanContext() )[0];
		$closed  = ( new AiReadersCheck(
			static fn(): array => array(
				'guest_comments' => 'closed',
				'registration'   => 'closed',
				'robots'         => "User-agent: *\nDisallow: /\n",
			)
		) )->run( new ScanContext() )[0];
		$partial = ( new AiReadersCheck(
			static fn(): array => array(
				'guest_comments' => 'closed',
				'registration'   => 'closed',
				'robots'         => "User-agent: GPTBot\nDisallow: /\n",
			)
		) )->run( new ScanContext() )[0];
		$unread  = ( new AiReadersCheck(
			static fn(): array => array(
				'guest_comments' => 'closed',
				'registration'   => 'closed',
				'robots'         => null,
			)
		) )->run( new ScanContext() )[0];
		$unknown = ( new AiReadersCheck(
			static fn(): array => array(
				'guest_comments' => null,
				'registration'   => 'closed',
				'robots'         => '',
			)
		) )->run( new ScanContext() )[0];

		self::assertSame( 'warn', $open->state );
		self::assertStringContainsString( 'Guests can comment', $open->summary );
		self::assertStringContainsString( 'anyone can register', $open->summary );
		self::assertStringContainsString( 'not asked to stay out', $open->summary );
		self::assertStringContainsString( 'does not change', $open->summary );
		self::assertStringContainsString( 'content API', $open->summary );
		self::assertSame( 'allowed', $open->evidence['ai_crawlers'] );
		self::assertStringNotContainsString( 'safe', $open->summary );

		self::assertSame( 'pass', $closed->state );
		self::assertSame( 'blocked', $closed->evidence['ai_crawlers'] );
		self::assertStringContainsString( 'stay out', $closed->summary );

		self::assertSame( 'pass', $partial->state );
		self::assertSame( 'limited', $partial->evidence['ai_crawlers'] );
		self::assertSame( 'unknown', $unread->evidence['ai_crawlers'] );
		self::assertStringContainsString( 'could not be read', $unread->summary );
		self::assertSame( 'unknown', $unknown->state );
		self::assertStringNotContainsString( 'Registration is closed', $unknown->summary );
		$openUnknown = ( new AiReadersCheck(
			static fn(): array => array(
				'guest_comments' => 'open',
				'registration'   => null,
				'robots'         => '',
			)
		) )->run( new ScanContext() )[0];
		self::assertSame( 'warn', $openUnknown->state );
		self::assertStringContainsString( 'registration setting could not be read', $openUnknown->summary );
		self::assertStringNotContainsString( 'Registration is closed', $openUnknown->summary );
	}

	public function test_ai_readiness_reports_sign_in_tools_and_does_not_send_the_site(): void {
		$open   = ( new AiReadinessCheck(
			static fn(): array => array(
				'app_passwords'   => 'open',
				'assistant'       => 'off',
				'assistant_ready' => 'no',
				'guide'           => 'absent',
			)
		) )->run( new ScanContext() )[0];
		$on     = ( new AiReadinessCheck(
			static fn(): array => array(
				'app_passwords'   => 'closed',
				'assistant'       => 'on',
				'assistant_ready' => 'yes',
				'guide'           => 'present',
			)
		) )->run( new ScanContext() )[0];
		$both   = ( new AiReadinessCheck(
			static fn(): array => array(
				'app_passwords'   => 'open',
				'assistant'       => 'on',
				'assistant_ready' => 'yes',
				'guide'           => 'absent',
			)
		) )->run( new ScanContext() )[0];
		$quiet  = ( new AiReadinessCheck(
			static fn(): array => array(
				'app_passwords'   => 'closed',
				'assistant'       => 'off',
				'assistant_ready' => 'no',
				'guide'           => 'absent',
			)
		) )->run( new ScanContext() )[0];
		$unread = ( new AiReadinessCheck( static fn(): array => array() ) )->run( new ScanContext() )[0];

		self::assertSame( 'warn', $open->state );
		self::assertStringContainsString( 'Application passwords are available', $open->summary );
		self::assertStringContainsString( 'not ready to connect an assistant', $open->summary );
		self::assertStringContainsString( 'No llms.txt guide', $open->summary );
		self::assertStringContainsString( 'does not send', $open->summary );
		self::assertStringNotContainsString( 'safe', $open->summary );
		self::assertSame( 'disable-application-passwords', StartHere::control( $open )['operation'] );

		self::assertSame( 'warn', $on->state );
		self::assertStringContainsString( 'AI assistant access is on', $on->summary );
		self::assertStringContainsString( 'llms.txt guide is published', $on->summary );
		self::assertSame( 'amsec-assistant', StartHere::control( $on )['page'] );
		self::assertSame( 'amsec-mcp', StartHere::control( $on )['hash'] );
		self::assertSame( 'amsec-mcp', StartHere::control( $both )['hash'] );

		self::assertSame( 'pass', $quiet->state );
		self::assertStringContainsString( 'turned off', $quiet->summary );
		self::assertNull( StartHere::control( $quiet ) );
		$paused = ( new AiReadinessCheck(
			static fn(): array => array(
				'app_passwords'   => 'plugin-off',
				'assistant'       => 'off',
				'assistant_ready' => 'no',
				'guide'           => 'absent',
			)
		) )->run( new ScanContext() )[0];
		self::assertSame( 'pass', $paused->state );
		self::assertStringContainsString( 'Saved passwords stay stored', $paused->summary );
		self::assertSame( 'enable-application-passwords', StartHere::control( $paused )['operation'] );
		self::assertSame( 'unknown', $unread->state );
		self::assertStringContainsString( 'could not be read', $unread->summary );
	}

	public function test_known_holes_use_the_stored_result_and_do_not_contact_a_provider(): void {
		$off     = ( new KnownHolesCheck(
			static fn(): array => array(
				'enabled' => 'no',
				'stored'  => 'none',
				'found'   => 0,
			)
		) )->run( new ScanContext() )[0];
		$waiting = ( new KnownHolesCheck(
			static fn(): array => array(
				'enabled' => 'yes',
				'stored'  => 'none',
				'found'   => 0,
			)
		) )->run( new ScanContext() )[0];
		$found   = ( new KnownHolesCheck(
			static fn(): array => array(
				'enabled' => 'yes',
				'stored'  => 'found',
				'found'   => 2,
			)
		) )->run( new ScanContext() )[0];
		$clean   = ( new KnownHolesCheck(
			static fn(): array => array(
				'enabled' => 'yes',
				'stored'  => 'clean',
				'found'   => 0,
			)
		) )->run( new ScanContext() )[0];
		$unread  = ( new KnownHolesCheck(
			static fn(): array => array(
				'enabled' => null,
				'stored'  => 'none',
				'found'   => 0,
			)
		) )->run( new ScanContext() )[0];

		self::assertSame( 'warn', $off->state );
		self::assertStringContainsString( 'not being checked', $off->summary );
		self::assertStringContainsString( 'does not contact', $off->summary );
		self::assertStringNotContainsString( 'safe', $off->summary );
		self::assertSame( 'warn', $waiting->state );
		self::assertStringContainsString( 'no result is stored', $waiting->summary );
		self::assertSame( 'warn', $found->state );
		self::assertStringContainsString( 'published issue', $found->summary );
		self::assertSame( 2, $found->evidence['found_count'] );
		self::assertSame( 'pass', $clean->state );
		self::assertSame( 'unknown', $unread->state );
	}

	public function test_later_follow_ups_read_stored_results_and_do_not_start_a_scan(): void {
		$expect = array(
			'release-files'    => array(
				'none'  => 'have not been compared',
				'found' => 'does not match',
				'clean' => 'did not record',
			),
			'closed-plugins'   => array(
				'none'  => 'have not been checked',
				'found' => 'closed on WordPress.org',
				'clean' => 'did not find a closed plugin',
			),
			'public-content'   => array(
				'none'  => 'have not been checked',
				'found' => 'suspicious-content rule',
				'clean' => 'did not record a suspicious link',
			),
			'suspicious-files' => array(
				'none'  => 'has not been checked',
				'found' => 'suspicious-code rule',
				'clean' => 'did not record a suspicious-code match',
			),
			'local-inventory'  => array(
				'none'  => 'have not been inventoried',
				'found' => 'selected public file name',
				'clean' => 'did not list a selected public file name',
			),
			'security-headers' => array(
				'none'  => 'have not been checked',
				'found' => 'response header was missing',
				'clean' => 'did not record a missing selected header',
			),
		);
		foreach ( $expect as $id => $lines ) {
			$none  = ( new FollowUpCheck(
				$id,
				static fn(): array => array(
					'stored' => 'none',
					'found'  => 0,
				)
			) )->run( new ScanContext() )[0];
			$found = ( new FollowUpCheck(
				$id,
				static fn(): array => array(
					'stored' => 'found',
					'found'  => 1,
				)
			) )->run( new ScanContext() )[0];
			$clean = ( new FollowUpCheck(
				$id,
				static fn(): array => array(
					'stored' => 'clean',
					'found'  => 0,
				)
			) )->run( new ScanContext() )[0];
			self::assertSame( 'warn', $none->state );
			self::assertStringContainsString( $lines['none'], $none->summary );
			self::assertStringContainsString( 'does not start', $none->summary );
			self::assertStringNotContainsString( 'safe', $none->summary );
			self::assertSame( 'warn', $found->state );
			self::assertStringContainsString( $lines['found'], $found->summary );
			self::assertSame( 1, $found->evidence['found_count'] );
			self::assertSame( 'pass', $clean->state );
			self::assertStringContainsString( $lines['clean'], $clean->summary );
			self::assertNull( StartHere::control( $clean ) );
		}
		$unread = ( new FollowUpCheck(
			'release-files',
			static fn(): array => array(
				'stored' => null,
				'found'  => 0,
			)
		) )->run( new ScanContext() )[0];
		self::assertSame( 'unknown', $unread->state );
		$off     = ( new KnownHolesCheck(
			static fn(): array => array(
				'enabled' => 'no',
				'stored'  => 'none',
				'found'   => 0,
			)
		) )->run( new ScanContext() )[0];
		$files   = ( new FollowUpCheck(
			'release-files',
			static fn(): array => array(
				'stored' => 'none',
				'found'  => 0,
			)
		) )->run( new ScanContext() )[0];
		$plugins = ( new FollowUpCheck(
			'closed-plugins',
			static fn(): array => array(
				'stored' => 'none',
				'found'  => 0,
			)
		) )->run( new ScanContext() )[0];
		$content = ( new FollowUpCheck(
			'public-content',
			static fn(): array => array(
				'stored' => 'none',
				'found'  => 0,
			)
		) )->run( new ScanContext() )[0];
		self::assertSame( 'amsec_security_scanner_vulnerability_enable', StartHere::control( $off )['action'] );
		self::assertSame( 'amsec_security_scanner_integrity_start', StartHere::control( $files )['action'] );
		self::assertSame( 'amsec-repository', StartHere::control( $plugins )['page'] );
		self::assertSame( 'amsec_content_scan', StartHere::control( $content )['action'] );
		$filescan = ( new FollowUpCheck(
			'suspicious-files',
			static fn(): array => array(
				'stored' => 'none',
				'found'  => 0,
			)
		) )->run( new ScanContext() )[0];
		self::assertSame( 'amsec_security_scanner_file_scan_start', StartHere::control( $filescan )['action'] );
		$update     = new CheckResult( 'core-updates', 'warn', 'A WordPress update is waiting.', 'https://developer.wordpress.org/advanced-administration/security/hardening/', new DateTimeImmutable( '2026-10-01T00:00:00Z' ), 'high', 'complete', array() );
		$updateDone = new CheckResult( 'core-updates', 'pass', 'WordPress does not report a core update waiting.', 'https://developer.wordpress.org/advanced-administration/security/hardening/', new DateTimeImmutable( '2026-10-01T00:00:00Z' ), 'high', 'complete', array() );
		$login      = new CheckResult( 'login-rate-mode', 'warn', 'Login monitoring is off.', 'https://developer.wordpress.org/advanced-administration/security/brute-force/', new DateTimeImmutable( '2026-10-01T00:00:00Z' ), 'high', 'complete', array( 'mode' => 'off' ) );
		$ping       = ( new PingbackCheck( static fn(): string => 'open' ) )->run( new ScanContext() )[0];
		self::assertSame( 'update-core.php', StartHere::control( $update )['screen'] );
		self::assertNull( StartHere::control( $updateDone ) );
		self::assertSame( 'amsec-accounts', StartHere::control( $login )['page'] );
		self::assertSame( 'sign-in', StartHere::control( $login )['hash'] );
		self::assertSame( 'close-pingbacks', StartHere::control( $ping )['operation'] );
		self::assertArrayNotHasKey( 'screen', StartHere::control( $ping ) );
		$editor = new CheckResult( 'file-editor', 'warn', 'People can edit theme and plugin files in wp-admin.', 'https://developer.wordpress.org/advanced-administration/security/hardening/', new DateTimeImmutable( '2026-10-01T00:00:00Z' ), 'high', 'complete', array( 'fix' => 'plugin' ) );
		$config = new CheckResult( 'file-editor', 'warn', 'People can edit theme and plugin files because wp-config.php turns the editor on.', 'https://developer.wordpress.org/advanced-administration/security/hardening/', new DateTimeImmutable( '2026-10-01T00:00:00Z' ), 'high', 'complete', array( 'fix' => 'config' ) );
		self::assertSame( 'disable-file-editor', StartHere::control( $editor )['operation'] );
		self::assertSame( 'amsec-recovery', StartHere::control( $config )['page'] );
		self::assertArrayNotHasKey( 'action', StartHere::control( $config ) );
		$inventory = ( new FollowUpCheck(
			'local-inventory',
			static fn(): array => array(
				'stored' => 'none',
				'found'  => 0,
			)
		) )->run( new ScanContext() )[0];
		$headers   = ( new FollowUpCheck(
			'security-headers',
			static fn(): array => array(
				'stored' => 'none',
				'found'  => 0,
			)
		) )->run( new ScanContext() )[0];
		self::assertSame( 'amsec-exposure', StartHere::control( $inventory )['page'] );
		self::assertSame( 'amsec-headers', StartHere::control( $headers )['page'] );
	}

	public function test_file_modes_bot_controls_and_rest_limits_do_not_change_settings(): void {
		$dir = sys_get_temp_dir() . '/amsec-modes-' . bin2hex( random_bytes( 4 ) );
		mkdir( $dir, 0700 );
		$file = $dir . '/config.php';
		file_put_contents( $file, 'x' );
		chmod( $file, 0600 );
		$file = realpath( $file );
		try {
			$quiet = ( new FileModesCheck( array( 'configuration' => $file ) ) )->run( new ScanContext() )[0];
			chmod( $file, 0644 );
			$open = ( new FileModesCheck( array( 'configuration' => $file ) ) )->run( new ScanContext() )[0];
		} finally {
			chmod( $file, 0600 );
			unlink( $file );
			rmdir( $dir );
		}
		self::assertSame( 'pass', $quiet->state );
		self::assertStringContainsString( 'does not change file modes', $quiet->summary );
		self::assertStringNotContainsString( 'safe', $quiet->summary );
		self::assertNull( StartHere::control( $quiet ) );
		self::assertSame( 'warn', $open->state );
		self::assertSame( 'amsec-recovery', StartHere::control( $open )['page'] );
		self::assertStringNotContainsString( $file, $open->summary );

		$bots   = ( new BotModeCheck( static fn(): string => 'off' ) )->run( new ScanContext() )[0];
		$botsOn = ( new BotModeCheck( static fn(): string => 'block' ) )->run( new ScanContext() )[0];
		self::assertSame( 'warn', $bots->state );
		self::assertStringContainsString( 'does not change that setting', $bots->summary );
		self::assertStringNotContainsString( 'safe', $bots->summary );
		self::assertSame( 'amsec-bots', StartHere::control( $bots )['page'] );
		self::assertSame( 'pass', $botsOn->state );
		self::assertNull( StartHere::control( $botsOn ) );

		$rest    = ( new RestRateCheck( static fn(): mixed => null ) )->run( new ScanContext() )[0];
		$blocked = ( new RestRateCheck(
			static fn(): string => (string) json_encode(
				array(
					'version'    => 1,
					'mode'       => 'block',
					'exemptions' => array(),
					'revision'   => str_repeat( 'a', 32 ),
				)
			)
		) )->run( new ScanContext() )[0];
		$unread  = ( new RestRateCheck( static fn(): string => 'nope' ) )->run( new ScanContext() )[0];
		self::assertSame( 'warn', $rest->state );
		self::assertSame( 'off', $rest->evidence['mode'] );
		self::assertStringContainsString( 'does not change that policy', $rest->summary );
		self::assertStringNotContainsString( 'safe', $rest->summary );
		self::assertSame( 'amsec-rest-rates', StartHere::control( $rest )['page'] );
		self::assertSame( 'pass', $blocked->state );
		self::assertNull( StartHere::control( $blocked ) );
		self::assertSame( 'unknown', $unread->state );
	}

	public function test_watch_rows_link_only_when_the_setting_needs_review(): void {
		$emails = ( new SiteWatchCheck( 'finding-emails', static fn(): array => array( 'status' => 'off' ) ) )->run( new ScanContext() )[0];
		$digest = ( new SiteWatchCheck( 'weekly-digest', static fn(): array => array( 'status' => 'off' ) ) )->run( new ScanContext() )[0];
		$traffic = ( new SiteWatchCheck( 'traffic-history', static fn(): array => array( 'status' => 'off' ) ) )->run( new ScanContext() )[0];
		$network = ( new SiteWatchCheck( 'network-controls', static fn(): array => array( 'status' => 'off' ) ) )->run( new ScanContext() )[0];
		$blocked = ( new SiteWatchCheck( 'network-controls', static fn(): array => array( 'status' => 'block' ) ) )->run( new ScanContext() )[0];
		$proxies = ( new SiteWatchCheck( 'trusted-proxies', static fn(): array => array( 'status' => 'off' ) ) )->run( new ScanContext() )[0];
		$forwarded = ( new SiteWatchCheck( 'trusted-proxies', static fn(): array => array( 'status' => 'xff' ) ) )->run( new ScanContext() )[0];

		self::assertSame( 'warn', $emails->state );
		self::assertSame( 'amsec-settings', StartHere::control( $emails )['page'] );
		self::assertSame( 'amsec-alerts', StartHere::control( $emails )['hash'] );
		self::assertSame( 'amsec-digest', StartHere::control( $digest )['page'] );
		self::assertSame( 'amsec-traffic', StartHere::control( $traffic )['page'] );
		self::assertStringContainsString( 'Visitor addresses are not stored', $traffic->summary );
		self::assertSame( 'pass', $network->state );
		self::assertNull( StartHere::control( $network ) );
		self::assertSame( 'warn', $blocked->state );
		self::assertSame( 'amsec-network', StartHere::control( $blocked )['page'] );
		self::assertSame( 'pass', $proxies->state );
		self::assertNull( StartHere::control( $proxies ) );
		self::assertSame( 'warn', $forwarded->state );
		self::assertSame( 'amsec-proxies', StartHere::control( $forwarded )['page'] );
		foreach ( array( $emails, $digest, $traffic, $network, $blocked, $proxies, $forwarded ) as $row ) {
			self::assertStringContainsString( 'does not change that setting', $row->summary );
			self::assertStringNotContainsString( 'safe', $row->summary );
		}

		self::assertSame( 'off', SiteWatchCheck::emails( false ) );
		self::assertSame( 'off', SiteWatchCheck::emails( null ) );
		self::assertSame( 'on', SiteWatchCheck::emails( '1' ) );
		self::assertSame( 'off', SiteWatchCheck::emails( '0' ) );
		self::assertSame( 'off', SiteWatchCheck::digest( null ) );
		self::assertSame( 'on', SiteWatchCheck::digest( '1' ) );
		self::assertSame( 'off', SiteWatchCheck::traffic( null ) );
		self::assertSame( 'unknown', SiteWatchCheck::traffic( 'nope' ) );
		self::assertSame( 'off', SiteWatchCheck::network( null ) );
		self::assertSame( 'off', SiteWatchCheck::proxies( null ) );
		$forward = (string) json_encode(
			array(
				'version'  => 1,
				'mode'     => 'xff',
				'cidrs'    => array( '203.0.113.0/24' ),
				'revision' => str_repeat( 'c', 32 ),
			)
		);
		self::assertSame( 'xff', SiteWatchCheck::proxies( $forward ) );

		$activity = ( new SiteWatchCheck( 'security-activity', static fn(): array => array( 'status' => 'off' ) ) )->run( new ScanContext() )[0];
		$recording = ( new SiteWatchCheck( 'security-activity', static fn(): array => array( 'status' => 'on' ) ) )->run( new ScanContext() )[0];
		$baseline = ( new SiteWatchCheck( 'code-baselines', static fn(): array => array( 'status' => 'none' ) ) )->run( new ScanContext() )[0];
		$stored = ( new SiteWatchCheck( 'code-baselines', static fn(): array => array( 'status' => 'stored' ) ) )->run( new ScanContext() )[0];
		self::assertSame( 'warn', $activity->state );
		self::assertSame( 'amsec-activity', StartHere::control( $activity )['page'] );
		self::assertSame( 'pass', $recording->state );
		self::assertNull( StartHere::control( $recording ) );
		self::assertSame( 'warn', $baseline->state );
		self::assertStringContainsString( 'does not prove that code is clean', $baseline->summary );
		self::assertStringNotContainsString( 'safe', $baseline->summary );
		self::assertSame( 'amsec-baselines', StartHere::control( $baseline )['page'] );
		self::assertSame( 'pass', $stored->state );
		self::assertNull( StartHere::control( $stored ) );
		self::assertSame( 'off', SiteWatchCheck::activity( null ) );
		self::assertSame( 'on', SiteWatchCheck::activity( '1' ) );
		self::assertSame( 'none', SiteWatchCheck::baselines( null ) );
		self::assertSame( 'stored', SiteWatchCheck::baselines( '{"version":1,"baselines":{"plugin":{}},"previews":[]}' ) );
		self::assertSame( 'preview', SiteWatchCheck::baselines( '{"version":1,"baselines":[],"previews":{"1":{}}}' ) );
		self::assertSame( 'unknown', SiteWatchCheck::baselines( '{' ) );

		$extra = ( new SiteWatchCheck( 'account-sessions', static fn(): array => array( 'status' => 'extra' ) ) )->run( new ScanContext() )[0];
		$single = ( new SiteWatchCheck( 'account-sessions', static fn(): array => array( 'status' => 'single' ) ) )->run( new ScanContext() )[0];
		$daily = ( new SiteWatchCheck( 'daily-checks', static fn(): array => array( 'status' => 'never' ) ) )->run( new ScanContext() )[0];
		$done = ( new SiteWatchCheck( 'daily-checks', static fn(): array => array( 'status' => 'complete' ) ) )->run( new ScanContext() )[0];
		self::assertSame( 'warn', $extra->state );
		self::assertStringContainsString( 'does not revoke a session', $extra->summary );
		self::assertStringNotContainsString( 'safe', $extra->summary );
		self::assertSame( 'amsec-sessions', StartHere::control( $extra )['page'] );
		self::assertSame( 'pass', $single->state );
		self::assertNull( StartHere::control( $single ) );
		self::assertSame( 'warn', $daily->state );
		self::assertStringContainsString( 'does not start one', $daily->summary );
		self::assertStringNotContainsString( 'safe', $daily->summary );
		self::assertSame( 'amsec-schedule', StartHere::control( $daily )['hash'] );
		self::assertArrayNotHasKey( 'action', StartHere::control( $daily ) );
		self::assertSame( 'pass', $done->state );

		$files = ( new SiteWatchCheck( 'daily-file-checks', static fn(): array => array( 'status' => 'never' ) ) )->run( new ScanContext() )[0];
		$filesDone = ( new SiteWatchCheck( 'daily-file-checks', static fn(): array => array( 'status' => 'complete' ) ) )->run( new ScanContext() )[0];
		$rules = ( new SiteWatchCheck( 'rule-review', static fn(): array => array( 'status' => 'overdue' ) ) )->run( new ScanContext() )[0];
		$rulesOk = ( new SiteWatchCheck( 'rule-review', static fn(): array => array( 'status' => 'recent' ) ) )->run( new ScanContext() )[0];
		self::assertSame( 'warn', $files->state );
		self::assertStringContainsString( 'does not start one', $files->summary );
		self::assertSame( 'amsec-schedule', StartHere::control( $files )['hash'] );
		self::assertArrayNotHasKey( 'action', StartHere::control( $files ) );
		self::assertSame( 'pass', $filesDone->state );
		self::assertSame( 'warn', $rules->state );
		self::assertStringContainsString( 'does not download new rules', $rules->summary );
		self::assertStringContainsString( 'not a malware feed', $rules->summary );
		self::assertStringNotContainsString( 'safe', $rules->summary );
		self::assertSame( 'amsec-rules', StartHere::control( $rules )['page'] );
		self::assertSame( 'pass', $rulesOk->state );
		self::assertNull( StartHere::control( $rulesOk ) );
	}

	public function test_missing_two_factor_recommendation_installs_the_plugin(): void {
		$missing = new \AmazingPlugins\Security\Findings\CheckResult( 'authenticator-app', 'critical', 'x', 'https://wordpress.org/plugins/two-factor/', new \DateTimeImmutable(), 'high', 'complete', array( 'status' => 'missing' ) );
		$off     = new \AmazingPlugins\Security\Findings\CheckResult( 'passkeys-status', 'warn', 'x', 'https://wordpress.org/plugins/two-factor/', new \DateTimeImmutable(), 'medium', 'complete', array( 'status' => 'available' ) );
		self::assertSame( 'two-factor', StartHere::control( $missing )['install'] );
		self::assertSame( 'passkeys', StartHere::control( $off )['hash'] );
	}
}
