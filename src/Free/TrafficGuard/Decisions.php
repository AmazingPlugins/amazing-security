<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Free\TrafficGuard;

/** Local traffic decisions. Empty lists and the off option do nothing. */
final class Decisions {
	/** @return array<int, string> */
	public static function entries( string $raw ): array {
		$lines = preg_split( "/\r\n|\n|\r/", $raw );
		$out   = array();
		if ( ! is_array( $lines ) ) {
			return $out;
		}
		foreach ( $lines as $line ) {
			$line = trim( $line );
			if ( '' === $line || strlen( $line ) > 120 ) {
				continue;
			}
			$out[] = $line;
			if ( count( $out ) >= 20 ) {
				break;
			}
		}
		return $out;
	}

	public static function tooMany( string $raw ): bool {
		$lines = preg_split( "/\r\n|\n|\r/", $raw );
		$count = 0;
		if ( ! is_array( $lines ) ) {
			return false;
		}
		foreach ( $lines as $line ) {
			if ( '' !== trim( $line ) ) {
				++$count;
			}
		}
		return $count > 20;
	}

	/**
	 * @param array<int, string> $hosts
	 * @param array<int, string> $agents
	 * @param array<int, string> $referrers
	 */
	public static function blocked( array $hosts, array $agents, array $referrers, string $host, string $agent, string $referrer, bool $admin ): bool {
		return ( new BlockList() )->blocked(
			implode( "\n", $hosts ),
			implode( "\n", $agents ),
			implode( "\n", $referrers ),
			array(
				'HTTP_HOST'       => $host,
				'HTTP_USER_AGENT' => $agent,
				'HTTP_REFERER'    => $referrer,
			),
			$admin
		);
	}

	public static function path( string $uri ): string {
		return ( new LiveTraffic() )->path( $uri );
	}

	public static function hotlink( string $referrer, string $siteHost, string $file ): string {
		$hotlink = new Hotlink();
		if ( ! $hotlink->isUploadsImage( $file ) ) {
			return 'skip';
		}
		$blocked = $hotlink->blocked(
			true,
			array(
				'REQUEST_URI'  => $file,
				'HTTP_REFERER' => $referrer,
			),
			$siteHost
		);
		return $blocked ? 'block' : 'allow';
	}
}
