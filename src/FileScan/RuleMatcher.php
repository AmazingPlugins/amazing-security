<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\FileScan;

use RuntimeException;

final class RuleMatcher {
	public function __construct( private readonly BundledRulePack $pack ) {}

	/** @return RuleHit[] */
	public function match( string $bytes, string $relativePath ): array {
		if ( ! function_exists( 'token_get_all' ) || strlen( $bytes ) > 2097152 ) {
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
			throw new RuntimeException( 'rule_limit' );
		}
		$code     = '';
		$previous = null;
		foreach ( $tokens as $token ) {
			if ( ! is_array( $token ) ) {
				$code    .= $token;
				$previous = $token;
				continue;
			}
			if ( in_array( $token[0], array( T_COMMENT, T_DOC_COMMENT, T_INLINE_HTML, T_ENCAPSED_AND_WHITESPACE, T_START_HEREDOC, T_END_HEREDOC ), true ) ) {
				$code .= ' ' . str_repeat( "\n", substr_count( $token[1], "\n" ) );
			} elseif ( in_array( $token[0], array( T_NAME_QUALIFIED, T_NAME_RELATIVE ), true ) || ( T_NAME_FULLY_QUALIFIED === $token[0] && substr_count( $token[1], '\\' ) > 1 ) || ( T_VARIABLE === $token[0] && ! in_array( $token[1], array( '$_GET', '$_POST', '$_REQUEST', '$_COOKIE' ), true ) ) || ( T_STRING === $token[0] && in_array( $previous, array( T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR, T_DOUBLE_COLON, T_FUNCTION ), true ) ) ) {
				$code .= 'NON_GLOBAL_NAME';
			} elseif ( T_CONSTANT_ENCAPSED_STRING === $token[0] ) {
				if ( $this->hiddenExternalLink( $token[1] ) ) {
					$code .= "\x01HIDDEN_EXTERNAL_LINK\x02";
				} elseif ( preg_match( '/^[\'\"]Location:\s*[\'\"]$/i', $token[1] ) ) {
					$code .= "\x01LOCATION\x02";
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
			$result = preg_match( $rule['pattern'], $code, $match, PREG_OFFSET_CAPTURE );
			if ( false === $result ) {
				throw new RuntimeException( 'rule_limit' );
			}
			if ( 1 === $result ) {
				$hits[] = new RuleHit( $id, $this->pack->version(), $relativePath, 1 + substr_count( $code, "\n", 0, $match[0][1] ), $rule['summary'] );
			}
		}
		return $hits;
	}

	private function hiddenExternalLink( string $literal ): bool {
		if ( strlen( $literal ) > 4096 || ! str_contains( strtolower( $literal ), '<a' ) ) {
			return false;
		}
		preg_match_all( '/<a\b[^>]{0,1024}>/i', $literal, $tags );
		foreach ( $tags[0] as $tag ) {
			if ( preg_match( '/\bhref\s*=\s*[\'\"]?https?:\/\//i', $tag ) && preg_match( '/\bstyle\s*=\s*[\'\"]?[^>]{0,512}\b(?:display\s*:\s*none|visibility\s*:\s*hidden)/i', $tag ) ) {
				return true;
			}
		}
		return false;
	}
}
