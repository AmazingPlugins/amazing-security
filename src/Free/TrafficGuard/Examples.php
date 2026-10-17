<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Free\TrafficGuard;

defined( 'ABSPATH' ) || exit;

/** Recommended traffic-list lines. Each line already fits the list rules. */
final class Examples {
	/**
	 * @return list<string>
	 */
	public static function hostnames(): array {
		return array(
			'semalt.com',
			'buttons-for-website.com',
			'darodar.com',
			'priceg.com',
			'kambasoft.com',
			'videosprofitnetwork.com',
			'ranksonic.info',
			'ilovevitaly.com',
		);
	}

	/**
	 * @return list<string>
	 */
	public static function agents(): array {
		return array(
			'sqlmap/1.7.8#stable (https://sqlmap.org)',
			'Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)',
			'masscan/1.3 (https://github.com/robertdavidgraham/masscan)',
			'Mozilla/5.00 (Nikto/2.1.6)',
			'WPScan v3.8.28 (https://wpscan.com/wordpress-security-scanner)',
			'ZmEu',
		);
	}

	/**
	 * @return list<string>
	 */
	public static function referrers(): array {
		return array(
			'http://semalt.com/',
			'https://semalt.com/',
			'http://www.semalt.com/',
			'http://buttons-for-website.com/',
			'http://darodar.com/',
			'http://priceg.com/',
			'http://kambasoft.com/',
			'http://videosprofitnetwork.com/',
		);
	}
}
