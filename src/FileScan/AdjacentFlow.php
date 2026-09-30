<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\FileScan;

/** Recognizes only adjacent, explicit assignments. Never evaluates source. */
final class AdjacentFlow {
	public static function markers( array $tokens ): array {
		$items = array();
		foreach ( $tokens as $index => $token ) {
			if ( is_array( $token ) && in_array( $token[0], array( T_WHITESPACE, T_COMMENT, T_DOC_COMMENT ), true ) ) {
				continue;
			}
			$items[] = array( $index, is_array( $token ) ? $token[0] : null, is_array( $token ) ? $token[1] : $token );
		}
		$markers = array();
		$count   = count( $items );
		for ( $i = 1; $i < $count - 11; ++$i ) {
			if ( T_VARIABLE !== $items[ $i ][1] || '=' !== $items[ $i + 1 ][2] || ( ! in_array( $items[ $i - 1 ][2], array( ';', '{', '}' ), true ) && T_OPEN_TAG !== $items[ $i - 1 ][1] ) ) {
				continue;
			}
			$name = $items[ $i ][2];
			$j    = $i + 2;
			if ( self::request( $items, $j ) && ';' === ( $items[ $j + 4 ][2] ?? '' ) && T_STRING === ( $items[ $j + 5 ][1] ?? null ) && 'wp_redirect' === strtolower( $items[ $j + 5 ][2] ) && '(' === ( $items[ $j + 6 ][2] ?? '' ) && ( $items[ $j + 7 ][2] ?? '' ) === $name && in_array( $items[ $j + 8 ][2] ?? '', array( ')', ',' ), true ) ) {
				$markers[ $items[ $i ][0] ] = "\x01INDIRECT_REDIRECT\x02";
			}
			$literal = '';
			$pieces  = 0;
			while ( $j < $count && $pieces < 16 && T_CONSTANT_ENCAPSED_STRING === $items[ $j ][1] && preg_match( '/^[\'\"]([a-z_]*)[\'\"]$/iD', $items[ $j ][2], $match ) ) {
				$literal .= $match[1];
				++$pieces;
				++$j;
				if ( '.' !== ( $items[ $j ][2] ?? '' ) ) {
					break;
				}
				++$j;
			}
			if ( T_CONSTANT_ENCAPSED_STRING === ( $items[ $j - 1 ][1] ?? null ) && in_array( strtolower( $literal ), array( 'system', 'exec', 'shell_exec', 'passthru', 'proc_open' ), true ) && ';' === ( $items[ $j ][2] ?? '' ) && ( $items[ $j + 1 ][2] ?? '' ) === $name && '(' === ( $items[ $j + 2 ][2] ?? '' ) && self::request( $items, $j + 3 ) && in_array( $items[ $j + 7 ][2] ?? '', array( ')', ',' ), true ) ) {
				$markers[ $items[ $i ][0] ] = "\x01INDIRECT_COMMAND\x02";
			}
		}
		return $markers;
	}

	private static function request( array $items, int $index ): bool {
		return T_VARIABLE === ( $items[ $index ][1] ?? null ) && in_array( $items[ $index ][2], array( '$_GET', '$_POST', '$_REQUEST', '$_COOKIE' ), true ) && '[' === ( $items[ $index + 1 ][2] ?? '' ) && T_CONSTANT_ENCAPSED_STRING === ( $items[ $index + 2 ][1] ?? null ) && ']' === ( $items[ $index + 3 ][2] ?? '' );
	}
}
