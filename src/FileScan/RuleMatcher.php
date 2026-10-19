<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\FileScan;

defined( 'ABSPATH' ) || exit;

use RuntimeException;

final class RuleMatcher {
	public function __construct( private readonly BundledRulePack $pack, private readonly MalwareSignatures $signatures = new MalwareSignatures() ) {}

	/**
	 * Token rules first. Byte signatures report only when no token rule matched, and they alone cover files too large for tokens.
	 *
	 * @return RuleHit[]
	 */
	public function match( string $bytes, string $relativePath ): array {
		if ( strlen( $bytes ) > 2097152 ) {
			throw new RuntimeException( 'rule_unavailable' );
		}
		$tokens  = null;
		$refused = null;
		$failed  = array();
		try {
			$tokens = $this->tokens( $bytes );
		} catch ( RuntimeException $error ) {
			$refused = $error;
		}
		$signals = $this->signatures->scan( null === $tokens ? $bytes : MalwareSignatures::view( $tokens ), $failed );
		$hits    = array();
		if ( null !== $tokens ) {
			try {
				$hits = $this->tokenHits( $tokens, $relativePath, $failed );
			} catch ( RuntimeException $error ) {
				$refused = $error;
			}
		}
		// Any confirmed hit is reported. With none, a failed rule or a missing tokenizer leaves the file unchecked.
		// Files only too large for the token rules still count as checked by the byte signatures.
		if ( array() === $hits && array() === $signals ) {
			if ( null !== $refused && 'rule_memory_limit' !== $refused->getMessage() ) {
				throw $refused;
			}
			if ( array() !== $failed ) {
				throw new RuntimeException( 'rule_limit' );
			}
		}
		if ( array() !== $hits ) {
			return $hits;
		}
		$rules = $this->pack->rules();
		foreach ( $signals as $id => $line ) {
			if ( isset( $rules[ $id ]['summary'] ) ) {
				$hits[] = new RuleHit( $id, $this->pack->version(), $relativePath, $line, $rules[ $id ]['summary'] );
			}
		}
		return $hits;
	}

	/** @return array<int, array{0: int, 1: string, 2: int}|string> */
	private function tokens( string $bytes ): array {
		if ( ! function_exists( 'token_get_all' ) ) {
			throw new RuntimeException( 'rule_unavailable' );
		}
		// Token arrays can use hundreds of bytes per source byte. Refuse before allocation.
		$estimated = strlen( $bytes ) * 256 + 8388608;
		$rawLimit  = trim( (string) ini_get( 'memory_limit' ) );
		$limit     = -1;
		if ( preg_match( '/^([0-9]+)\s*([KMG]?)$/iD', $rawLimit, $parts ) ) {
			$factor = match ( strtoupper( $parts[2] ) ) {
				'G' => 1073741824, 'M' => 1048576, 'K' => 1024, default => 1 };
			$limit = (int) $parts[1] * $factor;
		}
		if ( $estimated > 67108864 || ( $limit >= 0 && memory_get_usage( true ) + $estimated > $limit ) ) {
			throw new RuntimeException( 'rule_memory_limit' );
		}
		$tokens = token_get_all( $bytes );
		if ( count( $tokens ) > 100000 ) {
			throw new RuntimeException( 'rule_memory_limit' );
		}
		return $tokens;
	}

	/**
	 * @param array<int, array{0: int, 1: string, 2: int}|string> $tokens
	 * @return RuleHit[]
	 */
	private function tokenHits( array $tokens, string $relativePath, array &$failed ): array {
		$markers  = AdjacentFlow::markers( $tokens );
		$code     = '';
		$previous = null;
		foreach ( $tokens as $index => $token ) {
			$code .= $markers[ $index ] ?? '';
			if ( ! is_array( $token ) ) {
				$code    .= $token;
				$previous = $token;
				continue;
			}
			$offset = T_INLINE_HTML === $token[0] ? $this->hiddenLinkOffset( $token[1] ) : null;
			if ( null !== $offset ) {
				$before = substr_count( substr( $token[1], 0, $offset ), "\n" );
				$code  .= str_repeat( "\n", $before ) . "\x01INLINE_HIDDEN_LINK\x02" . str_repeat( "\n", substr_count( $token[1], "\n" ) - $before );
			} elseif ( in_array( $token[0], array( T_COMMENT, T_DOC_COMMENT, T_INLINE_HTML, T_ENCAPSED_AND_WHITESPACE, T_START_HEREDOC, T_END_HEREDOC ), true ) ) {
				$code .= ' ' . str_repeat( "\n", substr_count( $token[1], "\n" ) );
			} elseif ( in_array( $token[0], array( T_NAME_QUALIFIED, T_NAME_RELATIVE ), true ) || ( T_NAME_FULLY_QUALIFIED === $token[0] && substr_count( $token[1], '\\' ) > 1 ) || ( T_VARIABLE === $token[0] && ! in_array( $token[1], array( '$_GET', '$_POST', '$_REQUEST', '$_COOKIE' ), true ) ) || ( T_STRING === $token[0] && in_array( $previous, array( T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR, T_DOUBLE_COLON, T_FUNCTION ), true ) ) ) {
				$code .= 'NON_GLOBAL_NAME';
			} elseif ( T_CONSTANT_ENCAPSED_STRING === $token[0] ) {
				if ( $this->evalModifier( $token[1] ) ) {
					$code .= "\x01PREG_E\x02";
				} elseif ( $this->hiddenExternalLink( $token[1] ) ) {
					$code .= "\x01HIDDEN_EXTERNAL_LINK\x02";
				} elseif ( preg_match( '/^[\'\"]Location:\s*[\'\"]$/i', $token[1] ) ) {
					$code .= "\x01LOCATION\x02";
				} elseif ( preg_match( '/^[\'\"]Refresh:\s*0\s*;\s*url\s*=\s*[\'\"]$/i', $token[1] ) ) {
					$code .= "\x01REFRESH\x02";
				} elseif ( preg_match( '/^[\'\"]data:\/\//i', $token[1] ) ) {
					$code .= "\x01DATA_URI\x02";
				} else {
					$code .= preg_match( '/^[\'\"]https?:\/\//i', $token[1] ) ? "\x01URL\x02" : 'S';
				}
				$code .= str_repeat( "\n", substr_count( $token[1], "\n" ) );
			} else {
				$code .= $token[1];
			}
			if ( ! in_array( $token[0], array( T_WHITESPACE, T_COMMENT, T_DOC_COMMENT ), true ) ) {
				$previous = $token[0];
			}
		}
		$hits = array();
		foreach ( $this->pack->rules() as $id => $rule ) {
			if ( ! isset( $rule['pattern'] ) ) {
				continue;
			}
			$result = preg_match( $rule['pattern'], $code, $match, PREG_OFFSET_CAPTURE );
			if ( false === $result ) {
				$failed[] = $id;
				continue;
			}
			if ( 1 === $result ) {
				$hits[] = new RuleHit( $id, $this->pack->version(), $relativePath, 1 + substr_count( $code, "\n", 0, $match[0][1] ), $rule['summary'] );
			}
		}
		return $hits;
	}

	private function evalModifier( string $literal ): bool {
		if ( strlen( $literal ) > 512 || ! preg_match( '/^[\'\"](.*)[\'\"]$/s', $literal, $match ) ) {
			return false;
		}
		return 1 === preg_match( '/^(.)(?:\\\\.|(?!\\1).)*\\1[A-Za-z]*e[A-Za-z]*$/s', $match[1] );
	}

	private function hiddenExternalLink( string $literal ): bool {
		return null !== $this->hiddenLinkOffset( $literal );
	}

	private function hiddenLinkOffset( string $literal ): ?int {
		if ( strlen( $literal ) > 4096 || ! str_contains( strtolower( $literal ), '<a' ) ) {
			return null;
		}
		// Remove inert/raw-text contexts without changing byte offsets or line numbers.
		$markup = preg_replace_callback( '~<!--.*?(?:-->|$)|<(script|style|textarea|title)\b[^>]*>.*?(?:</\1\s*>|$)~is', static fn ( array $m ): string => preg_replace( '/[^\n]/', ' ', $m[0] ), $literal );
		if ( null === $markup ) {
			return null;
		}
		preg_match_all( '/<a\b(?:"[^"]*"|\'[^\']*\'|[^\'">])*+>/i', $markup, $tags, PREG_OFFSET_CAPTURE );
		foreach ( $tags[0] as $tag ) {
			preg_match_all( '/\s+([a-z_:][a-z0-9_.:-]*)\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s"\'=<>`]+))/i', $tag[0], $attributes, PREG_SET_ORDER | PREG_UNMATCHED_AS_NULL );
			$values = array();
			foreach ( $attributes as $attribute ) {
				$key = strtolower( $attribute[1] );
				if ( ! isset( $values[ $key ] ) ) {
					$values[ $key ] = $attribute[2] ?? $attribute[3] ?? $attribute[4] ?? '';
				}
			}
			if ( preg_match( '~^https?://~i', $values['href'] ?? '' ) && preg_match( '/(?:^|;)\s*(?:display\s*:\s*none|visibility\s*:\s*hidden)\s*(?:!important\s*)?(?:;|$)/i', $values['style'] ?? '' ) ) {
				return $tag[1];
			}
		}
		return null;
	}
}
