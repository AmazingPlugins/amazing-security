<?php
namespace AmazingPlugins\Security\Tests\Unit\Bots;

use AmazingPlugins\Security\Bots\ProbePolicy;
use PHPUnit\Framework\TestCase;

final class ProbePolicyTest extends TestCase {
	private static function path( string $path ): bool {
		return ProbePolicy::path( $path, static fn( string $slug ): bool => in_array( $slug, array( 'akismet', 'woocommerce' ), true ) );
	}

	public function test_probe_paths_are_hits(): void {
		foreach ( array( '/.env', '/blog/.env', '/.env.backup', '/.git/config', '/.git/HEAD', '/.git', '/wp-config.php.bak', '/wp-config.php.old', '/wp-config.php.save', '/wp-config.php.orig', '/wp-config.php~', '/wp-config.php.txt', '/wp-config.bak', '/phpinfo.php', '/info.php', '/adminer.php', '/wp-content/uploads/wso.php', '/alfa.php', '/shell.php', '/c99.php', '/r57.php', '/b374k.php', '/up.php', '/xleet.php', '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php', '/wp-content/plugins/revslider/readme.txt', '/%2eenv', '/PHPINFO.PHP' ) as $probe ) {
			self::assertTrue( self::path( $probe ), $probe );
		}
	}

	public function test_normal_pages_and_installed_plugin_readmes_are_not_hits(): void {
		foreach ( array( '/', '/about/', '/2024/01/hello-world/', '/wp-content/plugins/akismet/readme.txt', '/wp-content/plugins/woocommerce/readme.txt', '/wp-config.php', '/environment/', '/.envelope', '/my-info.php.html', '/digit/', '/shop/startup.php', '/vendor/phpunitx', '/readme.txt', '/wp-login.php' ) as $page ) {
			self::assertFalse( self::path( $page ), $page );
		}
	}

	public function test_attack_tool_agents_match_case_insensitively(): void {
		foreach ( array( 'sqlmap/1.7', 'Mozilla/5.00 (Nikto/2.5.0)', 'WPScan v3.8', 'Nuclei - Open-source project', 'masscan/1.3', 'zgrab/0.x', 'Acunetix', 'Nessus SOAP', 'DirBuster-1.0', 'gobuster/3.6', 'Fuzz Faster U Fool (ffuf) v2' ) as $agent ) {
			self::assertTrue( ProbePolicy::agent( $agent ), $agent );
		}
		foreach ( array( '', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 Safari/605.1.15', 'Googlebot/2.1', 'curl/8.4.0' ) as $agent ) {
			self::assertFalse( ProbePolicy::agent( $agent ), $agent );
		}
	}

	public function test_threshold_and_mode_decide_the_outcome(): void {
		self::assertSame( 'none', ProbePolicy::decide( 'block', null ) );
		self::assertSame( 'none', ProbePolicy::decide( 'block', 4 ) );
		self::assertSame( 'block', ProbePolicy::decide( 'block', 5 ) );
		self::assertSame( 'block', ProbePolicy::decide( 'block', 9 ) );
		self::assertSame( 'none', ProbePolicy::decide( 'watch', 4 ) );
		self::assertSame( 'flag', ProbePolicy::decide( 'watch', 5 ) );
		self::assertSame( 'flag', ProbePolicy::decide( 'watch', 50 ) );
		self::assertSame( 'none', ProbePolicy::decide( 'off', 50 ) );
		self::assertSame( 'none', ProbePolicy::decide( 'observe', 50 ) );
		self::assertSame( array( 5, 600, 3600 ), array( ProbePolicy::LIMIT, ProbePolicy::WINDOW, ProbePolicy::BLOCK ) );
	}
}
