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
		$tokens = token_get_all( $bytes );
		if ( count( $tokens ) > 100000 ) {
			throw new RuntimeException( 'rule_limit' );
		}
		$code = '';
		foreach ( $tokens as $token ) {
			if ( ! is_array( $token ) ) {
				$code .= $token;
				continue;
			}
			if ( in_array( $token[0], array( T_COMMENT, T_DOC_COMMENT, T_INLINE_HTML ), true ) ) {
				$code .= ' ' . str_repeat( "\n", substr_count( $token[1], "\n" ) );
			} elseif ( T_CONSTANT_ENCAPSED_STRING === $token[0] ) {
				$code .= preg_match( '/^[\'\"]https?:\/\//i', $token[1] ) ? 'URL' : 'S';
				$code .= str_repeat( "\n", substr_count( $token[1], "\n" ) );
			} else {
				$code .= $token[1];
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
}
