<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Bots;

defined( 'ABSPATH' ) || exit;

/** Pure rules for the scanner guard: which requests look like probing, and what to do after enough of them. */
final class ProbePolicy {
	public const LIMIT  = 5;
	public const WINDOW = 600;
	public const BLOCK  = 3600;

	private const AGENTS = array( 'sqlmap', 'nikto', 'wpscan', 'nuclei', 'masscan', 'zgrab', 'acunetix', 'nessus', 'dirbuster', 'gobuster', 'ffuf' );
	private const FILES  = array( 'phpinfo.php', 'info.php', 'adminer.php', 'wso.php', 'alfa.php', 'shell.php', 'c99.php', 'r57.php', 'b374k.php', 'up.php', 'xleet.php' );

	public static function agent( string $agent ): bool {
		$agent = strtolower( $agent );
		foreach ( self::AGENTS as $tool ) {
			if ( str_contains( $agent, $tool ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * @param string                 $path      Request path without the query string.
	 * @param callable(string): bool $installed Whether a plugin folder with this slug exists.
	 */
	public static function path( string $path, callable $installed ): bool {
		$path = strtolower( rawurldecode( $path ) );
		if ( 1 === preg_match( '~/\.env(\.[\w-]+)?$|/\.git(/|$)|/wp-config(\.php(\.bak|\.old|\.save|\.orig|\~|\.txt)|\.bak)$|/vendor/phpunit/~', $path ) ) {
			return true;
		}
		if ( in_array( basename( $path ), self::FILES, true ) ) {
			return true;
		}
		return 1 === preg_match( '~/wp-content/plugins/([^/]+)/readme\.txt$~', $path, $match ) && ! $installed( $match[1] );
	}

	/** Returns none, flag or block for a hit count inside the window. */
	public static function decide( string $mode, ?int $count ): string {
		if ( null === $count || $count < self::LIMIT || ! in_array( $mode, array( 'watch', 'block' ), true ) ) {
			return 'none';
		}
		return 'block' === $mode ? 'block' : 'flag';
	}
}
