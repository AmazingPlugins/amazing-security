<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Content;

defined( 'ABSPATH' ) || exit;

use RuntimeException;

/** Selected markup review patterns; never renders or evaluates input. */
final class MarkupDetector {
	public const VERSION = '2026.10.02.1';
	public const RULES   = array( 'AS-HTML-001', 'AS-HTML-002', 'AS-HTML-003', 'AS-HTML-004', 'AS-JS-001' );
	private const LIMITS = '(*LIMIT_MATCH=100000)(*LIMIT_RECURSION=1000)';
	public function __construct( private readonly string $siteHost ) {}

	public function match( string $body ): array {
		if ( strlen( $body ) > 131072 ) {
			throw new RuntimeException( 'content_item_limit' );
		}
		$hits          = array();
		$offset        = 0;
		$count         = 0;
		$templateDepth = 0;
		$length        = strlen( $body );
		// Consume every complete tag, including its quoted attributes, before looking for another.
		while ( $offset < $length ) {
			$next = strpos( $body, '<', $offset );
			if ( false === $next ) {
				break;
			}
			$offset = $next;
			if ( ++$count > 1000 ) {
				throw new RuntimeException( 'content_rule_limit' );
			}
			if ( substr( $body, $offset, 4 ) === '<!--' ) {
				$close  = strpos( $body, '-->', $offset + 4 );
				$offset = false === $close ? strlen( $body ) : $close + 3;
				continue;
			}
			$result = preg_match( '~' . self::LIMITS . '\G<(/?)([a-z][a-z0-9:-]*)(?=[\s/>])((?:"[^"]*"|\'[^\']*\'|[^\'">])*+)>~i', $body, $token, 0, $offset );
			if ( false === $result ) {
				throw new RuntimeException( 'content_rule_limit' );
			}
			if ( 0 === $result ) {
				++$offset;
				continue;
			}
			$tagOffset = $offset;
			$offset   += strlen( $token[0] );
			$name      = strtolower( $token[2] );
			if ( 'template' === $name ) {
				$templateDepth = '/' === $token[1] ? max( 0, $templateDepth - 1 ) : $templateDepth + 1;
				continue;
			}
			if ( '/' === $token[1] ) {
				continue;
			}
			if ( 'plaintext' === $name ) {
				break;
			}
			if ( in_array( $name, array( 'script', 'style', 'textarea', 'title', 'xmp', 'iframe', 'noembed', 'noframes' ), true ) ) {
				if ( 'iframe' === $name && 0 === $templateDepth ) {
					$frame = $this->attributes( $token[0] );
					$src   = $frame['src'] ?? '';
					if ( $this->external( $src ) && preg_match( '/(?:^|;)\s*(?:display\s*:\s*none|visibility\s*:\s*hidden)\s*(?:!important\s*)?(?:;|$)/i', $frame['style'] ?? '' ) ) {
						$this->hit( $hits, 'AS-HTML-004', $tagOffset, $body );
					}
				}
				$result = preg_match( '~' . self::LIMITS . '</' . $name . '\s*>~i', $body, $closing, PREG_OFFSET_CAPTURE, $offset );
				if ( false === $result ) {
					throw new RuntimeException( 'content_rule_limit' );
				}
				$end = $result ? $closing[0][1] : strlen( $body );
				if ( 'script' === $name && 0 === $templateDepth && $result ) {
					$this->script( $hits, $token[3], substr( $body, $offset, $end - $offset ), $tagOffset, $body );
				}
				$offset = $result ? $end + strlen( $closing[0][0] ) : $end;
				continue;
			}
			if ( $templateDepth > 0 || ! in_array( $name, array( 'a', 'meta' ), true ) ) {
				continue;
			}
			$tag        = array( array( $token[0], $tagOffset ), array( $name ) );
			$attributes = $this->attributes( $tag[0][0] );
			if ( 'a' === strtolower( $tag[1][0] ) ) {
				$href = $attributes['href'] ?? '';
				if ( $this->external( $href ) && preg_match( '/(?:^|;)\s*(?:display\s*:\s*none|visibility\s*:\s*hidden)\s*(?:!important\s*)?(?:;|$)/i', $attributes['style'] ?? '' ) ) {
					$this->hit( $hits, 'AS-HTML-001', $tag[0][1], $body );
				}
				if ( preg_match( '~^(?:javascript\s*:|data\s*:\s*text/html(?:[;,]|$))~i', $this->url( $href ) ) ) {
					$this->hit( $hits, 'AS-HTML-003', $tag[0][1], $body );
				}
			} elseif ( 'refresh' === strtolower( trim( $attributes['http-equiv'] ?? '' ) ) && preg_match( '~^\s*[0-9]+(?:\.[0-9]+)?\s*;\s*url\s*=\s*(.*?)\s*$~iD', $attributes['content'] ?? '', $match ) && $this->external( trim( $match[1], " \t\r\n\"'" ) ) ) {
				$this->hit( $hits, 'AS-HTML-002', $tag[0][1], $body );
			}
		}
		ksort( $hits );
		return array_values( $hits );
	}

	private function script( array &$hits, string $tag, string $bodyCode, int $offset, string $body ): void {
		$attributes = $this->attributes( ' ' . $tag );
		$type       = strtolower( trim( $attributes['type'] ?? '' ) );
		if ( isset( $attributes['src'] ) || ! in_array( $type, array( '', 'text/javascript', 'application/javascript', 'module' ), true ) ) {
			return;
		}
		$code = trim( $bodyCode );
		if ( preg_match( '~^\s*(?:window\.)?location(?:\.href)?\s*=\s*(["\'])([^"\'\\\\]{1,2048})\1\s*;?\s*$~D', $code, $match ) || preg_match( '~^\s*(?:window\.)?location\.(?:replace|assign)\s*\(\s*(["\'])([^"\'\\\\]{1,2048})\1\s*\)\s*;?\s*$~D', $code, $match ) ) {
			if ( $this->external( $match[2] ) ) {
				$this->hit( $hits, 'AS-JS-001', $offset, $body );
			}
		}
	}

	private function attributes( string $tag ): array {
		$result = preg_match_all( '~' . self::LIMITS . '\s+([a-z_:][a-z0-9_.:-]*)(?:\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s"\'=<>`]+)))?~i', $tag, $matches, PREG_SET_ORDER | PREG_UNMATCHED_AS_NULL );
		if ( false === $result || $result > 100 ) {
			throw new RuntimeException( 'content_rule_limit' );
		}
		$values = array();
		foreach ( $matches as $attribute ) {
			$key = strtolower( $attribute[1] );
			if ( ! isset( $values[ $key ] ) ) {
				$values[ $key ] = html_entity_decode( $attribute[2] ?? $attribute[3] ?? $attribute[4] ?? '', ENT_QUOTES | ENT_HTML5, 'UTF-8' );
			}
		}
		return $values;
	}

	private function external( string $value ): bool {
		$value = $this->url( $value );
		if ( strlen( $value ) > 2048 ) {
			return false;
		}
		if ( str_starts_with( $value, '//' ) ) {
			$value = 'https:' . $value;
		}
	 // phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url -- Pure PHP inert-markup tests run without WordPress.
		$parts = parse_url( $value );
		return is_array( $parts ) && in_array( strtolower( $parts['scheme'] ?? '' ), array( 'http', 'https' ), true ) && is_string( $parts['host'] ?? null ) && '' !== $parts['host'] && strtolower( rtrim( $parts['host'], '.' ) ) !== strtolower( rtrim( $this->siteHost, '.' ) );
	}

	private function url( string $value ): string {
		return str_replace( array( "\t", "\r", "\n" ), '', trim( $value ) );
	}
	private function hit( array &$hits, string $rule, int $offset, string $body ): void {
		$hits[ $rule ] ??= array(
			'rule' => $rule,
			'line' => 1 + substr_count( substr( $body, 0, $offset ), "\n" ),
		);
	}
}
