<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Free\TrafficGuard;

defined( 'ABSPATH' ) || exit;

/** Apache rule for image requests. Nginx does not read this file. */
final class HotlinkRule {
	public const BEGIN = '# Begin AmSec Security Scanner hotlink';

	public const END = '# End AmSec Security Scanner hotlink';

	public static function snippet( string $host ): string {
		$host = strtolower( trim( $host ) );
		$host = preg_replace( '/[^a-z0-9.-]/', '', $host ) ?? '';
		if ( '' === $host || str_contains( $host, '..' ) ) {
			return '';
		}
		$quoted = preg_quote( $host, '/' );
		return self::BEGIN . "\n<IfModule mod_rewrite.c>\nRewriteEngine On\nRewriteCond %{HTTP_REFERER} ^https?:// [NC]\nRewriteCond %{HTTP_REFERER} !^https?://(www\\.)?" . $quoted . "(:[0-9]+)?(/|$) [NC]\nRewriteRule \\.(jpe?g|png|gif|webp)$ - [F,NC,L]\n</IfModule>\n" . self::END . "\n";
	}

	public static function apply( string $existing, string $host, bool $enabled ): string {
		$stripped = self::strip( $existing );
		if ( ! $enabled ) {
			return $stripped;
		}
		$snippet = self::snippet( $host );
		if ( '' === $snippet ) {
			return $stripped;
		}
		$stripped = rtrim( $stripped );
		return '' === $stripped ? $snippet : $stripped . "\n\n" . $snippet;
	}

	public static function strip( string $existing ): string {
		$pattern = '/' . preg_quote( self::BEGIN, '/' ) . '.*?' . preg_quote( self::END, '/' ) . '\n?/s';
		$next    = preg_replace( $pattern, '', $existing );
		if ( ! is_string( $next ) ) {
			return $existing;
		}
		$next = trim( $next );
		return '' === $next ? '' : $next . "\n";
	}
}
