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
		for ( $i = 1; $i < $count - 3; ++$i ) {
			if ( T_VARIABLE !== $items[ $i ][1] || '=' !== $items[ $i + 1 ][2] || ( ! in_array( $items[ $i - 1 ][2], array( ';', '{', '}' ), true ) && T_OPEN_TAG !== $items[ $i - 1 ][1] ) ) {
				continue;
			}
			$name = $items[ $i ][2];
			$j    = $i + 2;
			if ( T_CONSTANT_ENCAPSED_STRING === ( $items[ $j ][1] ?? null ) && self::evalModifier( (string) $items[ $j ][2] ) && ';' === ( $items[ $j + 1 ][2] ?? '' ) ) {
				$pregCopied = self::copiedNames( $items, $name, $j + 1, 1 );
				$pregCall   = $pregCopied['at'] + 1;
				if ( T_STRING === ( $items[ $pregCall ][1] ?? null ) && 'preg_replace' === strtolower( (string) $items[ $pregCall ][2] ) && '(' === ( $items[ $pregCall + 1 ][2] ?? '' ) && T_VARIABLE === ( $items[ $pregCall + 2 ][1] ?? null ) && in_array( $items[ $pregCall + 2 ][2] ?? '', $pregCopied['names'], true ) ) {
					$markers[ $items[ $i ][0] ] = "\x01INDIRECT_PREG_E\x02";
				}
			}
			if ( self::request( $items, $j ) && ';' === ( $items[ $j + 4 ][2] ?? '' ) && T_STRING === ( $items[ $j + 5 ][1] ?? null ) && 'wp_redirect' === strtolower( $items[ $j + 5 ][2] ) && '(' === ( $items[ $j + 6 ][2] ?? '' ) && ( $items[ $j + 7 ][2] ?? '' ) === $name && in_array( $items[ $j + 8 ][2] ?? '', array( ')', ',' ), true ) ) {
				$markers[ $items[ $i ][0] ] = "\x01INDIRECT_REDIRECT\x02";
			}
			if ( T_STRING === ( $items[ $j ][1] ?? null ) && 'wp_remote_retrieve_body' === strtolower( (string) $items[ $j ][2] ) && '(' === ( $items[ $j + 1 ][2] ?? '' ) ) {
				$close = self::balancedClose( $items, $j + 1 );
				if ( $close > $j && ';' === ( $items[ $close + 1 ][2] ?? '' ) ) {
					$call = $close + 2;
					if ( T_EVAL === ( $items[ $call ][1] ?? null ) && '(' === ( $items[ $call + 1 ][2] ?? '' ) && T_VARIABLE === ( $items[ $call + 2 ][1] ?? null ) && ( $items[ $call + 2 ][2] ?? '' ) === $name && ')' === ( $items[ $call + 3 ][2] ?? '' ) ) {
						$markers[ $items[ $i ][0] ] = "\x01INDIRECT_HTTP_BODY_EVAL\x02";
					} else {
						$copied = self::copiedNames( $items, $name, $close + 1, 1 );
						$hop    = $copied['at'] + 1;
						if ( 2 === count( $copied['names'] ) && T_EVAL === ( $items[ $hop ][1] ?? null ) && '(' === ( $items[ $hop + 1 ][2] ?? '' ) && T_VARIABLE === ( $items[ $hop + 2 ][1] ?? null ) && in_array( $items[ $hop + 2 ][2] ?? '', $copied['names'], true ) && ')' === ( $items[ $hop + 3 ][2] ?? '' ) ) {
							$markers[ $items[ $i ][0] ] = "\x01INDIRECT_HTTP_BODY_EVAL_COPY\x02";
						} else {
							$copied = self::copiedNames( $items, $name, $close + 1, 2 );
							$hop    = $copied['at'] + 1;
							if ( 3 === count( $copied['names'] ) && T_EVAL === ( $items[ $hop ][1] ?? null ) && '(' === ( $items[ $hop + 1 ][2] ?? '' ) && T_VARIABLE === ( $items[ $hop + 2 ][1] ?? null ) && in_array( $items[ $hop + 2 ][2] ?? '', $copied['names'], true ) && ')' === ( $items[ $hop + 3 ][2] ?? '' ) ) {
								$markers[ $items[ $i ][0] ] = "\x01INDIRECT_HTTP_BODY_EVAL_COPY2\x02";
							}
						}
					}
				}
			}
			if ( T_CONSTANT_ENCAPSED_STRING === ( $items[ $j ][1] ?? null ) && preg_match( '/^[\'\"]data:\/\//i', (string) $items[ $j ][2] ) && ';' === ( $items[ $j + 1 ][2] ?? '' ) ) {
				$inc  = $j + 2;
				$kind = $items[ $inc ][1] ?? null;
				if ( in_array( $kind, array( T_INCLUDE, T_REQUIRE, T_INCLUDE_ONCE, T_REQUIRE_ONCE ), true ) ) {
					$open = ( $items[ $inc + 1 ][2] ?? '' ) === '(';
					$var  = $open ? ( $items[ $inc + 2 ][2] ?? '' ) : ( $items[ $inc + 1 ][2] ?? '' );
					$tail = $open ? ( $items[ $inc + 3 ][2] ?? '' ) : ( $items[ $inc + 2 ][2] ?? '' );
					if ( T_VARIABLE === ( $open ? ( $items[ $inc + 2 ][1] ?? null ) : ( $items[ $inc + 1 ][1] ?? null ) ) && $var === $name && ( $open ? ')' === $tail : ';' === $tail ) ) {
						$markers[ $items[ $i ][0] ] = "\x01INDIRECT_DATA_URI\x02";
					}
				} else {
					$copied = self::copiedNames( $items, $name, $j + 1, 1 );
					$hop    = $copied['at'] + 1;
					$kind   = $items[ $hop ][1] ?? null;
					if ( 2 === count( $copied['names'] ) && in_array( $kind, array( T_INCLUDE, T_REQUIRE, T_INCLUDE_ONCE, T_REQUIRE_ONCE ), true ) ) {
						$open = ( $items[ $hop + 1 ][2] ?? '' ) === '(';
						$var  = $open ? ( $items[ $hop + 2 ][2] ?? '' ) : ( $items[ $hop + 1 ][2] ?? '' );
						$tail = $open ? ( $items[ $hop + 3 ][2] ?? '' ) : ( $items[ $hop + 2 ][2] ?? '' );
						if ( T_VARIABLE === ( $open ? ( $items[ $hop + 2 ][1] ?? null ) : ( $items[ $hop + 1 ][1] ?? null ) ) && in_array( $var, $copied['names'], true ) && ( $open ? ')' === $tail : ';' === $tail ) ) {
							$markers[ $items[ $i ][0] ] = "\x01INDIRECT_DATA_URI_COPY\x02";
						}
					} else {
						$copied = self::copiedNames( $items, $name, $j + 1, 2 );
						$hop    = $copied['at'] + 1;
						$kind   = $items[ $hop ][1] ?? null;
						if ( 3 === count( $copied['names'] ) && in_array( $kind, array( T_INCLUDE, T_REQUIRE, T_INCLUDE_ONCE, T_REQUIRE_ONCE ), true ) ) {
							$open = ( $items[ $hop + 1 ][2] ?? '' ) === '(';
							$var  = $open ? ( $items[ $hop + 2 ][2] ?? '' ) : ( $items[ $hop + 1 ][2] ?? '' );
							$tail = $open ? ( $items[ $hop + 3 ][2] ?? '' ) : ( $items[ $hop + 2 ][2] ?? '' );
							if ( T_VARIABLE === ( $open ? ( $items[ $hop + 2 ][1] ?? null ) : ( $items[ $hop + 1 ][1] ?? null ) ) && in_array( $var, $copied['names'], true ) && ( $open ? ')' === $tail : ';' === $tail ) ) {
								$markers[ $items[ $i ][0] ] = "\x01INDIRECT_DATA_URI_COPY2\x02";
							}
						}
					}
				}
			}
			if ( self::request( $items, $j ) && ';' === ( $items[ $j + 4 ][2] ?? '' ) ) {
				$call  = $j + 5;
				$sinks = array(
					'extract'           => "\x01INDIRECT_EXTRACT\x02",
					'parse_str'         => "\x01INDIRECT_PARSE\x02",
					'file_put_contents' => "\x01INDIRECT_WRITE\x02",
				);
				if ( T_EVAL === ( $items[ $call ][1] ?? null ) && '(' === ( $items[ $call + 1 ][2] ?? '' ) && T_VARIABLE === ( $items[ $call + 2 ][1] ?? null ) && ( $items[ $call + 2 ][2] ?? '' ) === $name && ')' === ( $items[ $call + 3 ][2] ?? '' ) ) {
					$markers[ $items[ $i ][0] ] = "\x01INDIRECT_EVAL\x02";
				}
				$copied   = self::copiedNames( $items, $name, $j + 4 );
				$sinkCall = $copied['at'] + 1;
				$sinkName = strtolower( (string) ( $items[ $sinkCall ][2] ?? '' ) );
				$arg      = $items[ $sinkCall + 2 ][2] ?? '';
				if ( isset( $sinks[ $sinkName ] ) && T_STRING === ( $items[ $sinkCall ][1] ?? null ) && '(' === ( $items[ $sinkCall + 1 ][2] ?? '' ) && T_VARIABLE === ( $items[ $sinkCall + 2 ][1] ?? null ) && in_array( $arg, $copied['names'], true ) && in_array( $items[ $sinkCall + 3 ][2] ?? '', array( ')', ',' ), true ) ) {
					$markers[ $items[ $i ][0] ] = $sinks[ $sinkName ];
				}
				if ( T_VARIABLE === ( $items[ $call ][1] ?? null ) && ( $items[ $call ][2] ?? '' ) === $name && '(' === ( $items[ $call + 1 ][2] ?? '' ) && ! ( T_ELLIPSIS === ( $items[ $call + 2 ][1] ?? null ) && ')' === ( $items[ $call + 3 ][2] ?? '' ) ) ) {
					$markers[ $items[ $i ][0] ] = "\x01REQUEST_CALLBACK\x02";
				}
				$createCopied = self::copiedNames( $items, $name, $j + 4, 2 );
				$createCall   = $createCopied['at'] + 1;
				if ( T_STRING === ( $items[ $createCall ][1] ?? null ) && 'create_function' === strtolower( (string) ( $items[ $createCall ][2] ?? '' ) ) && '(' === ( $items[ $createCall + 1 ][2] ?? '' ) ) {
					$used   = $createCopied['names'];
					$second = T_CONSTANT_ENCAPSED_STRING === ( $items[ $createCall + 2 ][1] ?? null ) && ',' === ( $items[ $createCall + 3 ][2] ?? '' ) && T_VARIABLE === ( $items[ $createCall + 4 ][1] ?? null ) && in_array( $items[ $createCall + 4 ][2] ?? '', $used, true ) && in_array( $items[ $createCall + 5 ][2] ?? '', array( ')', ',' ), true );
					$first  = T_VARIABLE === ( $items[ $createCall + 2 ][1] ?? null ) && in_array( $items[ $createCall + 2 ][2] ?? '', $used, true ) && ',' === ( $items[ $createCall + 3 ][2] ?? '' );
					if ( $second || $first ) {
						$markers[ $items[ $i ][0] ] = "\x01INDIRECT_CREATE\x02";
					}
				}
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
			$calls  = array(
				'system'            => "\x01INDIRECT_COMMAND\x02",
				'exec'              => "\x01INDIRECT_COMMAND\x02",
				'shell_exec'        => "\x01INDIRECT_COMMAND\x02",
				'passthru'          => "\x01INDIRECT_COMMAND\x02",
				'proc_open'         => "\x01INDIRECT_COMMAND\x02",
				'assert'            => "\x01INDIRECT_ASSERT\x02",
				'extract'           => "\x01INDIRECT_EXTRACT\x02",
				'parse_str'         => "\x01INDIRECT_PARSE\x02",
				'file_put_contents' => "\x01INDIRECT_WRITE\x02",
			);
			$copied = self::copiedNames( $items, $name, $j );
			$use    = $copied['at'];
			if ( T_CONSTANT_ENCAPSED_STRING === ( $items[ $j - 1 ][1] ?? null ) && isset( $calls[ strtolower( $literal ) ] ) && ';' === ( $items[ $use ][2] ?? '' ) && ( $items[ $use + 1 ][2] ?? '' ) === $copied['name'] && '(' === ( $items[ $use + 2 ][2] ?? '' ) && self::request( $items, $use + 3 ) && in_array( $items[ $use + 7 ][2] ?? '', array( ')', ',' ), true ) ) {
				$markers[ $items[ $i ][0] ] = $calls[ strtolower( $literal ) ];
			}
		}
		return $markers;
	}

	private static function copiedNames( array $items, string $name, int $semicolon, int $limit = 5 ): array {
		$names = array( $name );
		$at    = $semicolon;
		for ( $hop = 0; $hop < $limit; ++$hop ) {
			$next = self::onceCopied( $items, $names[ count( $names ) - 1 ], $at );
			if ( $next['at'] === $at ) {
				break;
			}
			$names[] = $next['name'];
			$at      = $next['at'];
		}
		return array(
			'names' => $names,
			'name'  => $names[ count( $names ) - 1 ],
			'at'    => $at,
		);
	}

	private static function onceCopied( array $items, string $name, int $semicolon ): array {
		$next = $semicolon + 1;
		if ( T_VARIABLE === ( $items[ $next ][1] ?? null ) && '=' === ( $items[ $next + 1 ][2] ?? '' ) && ( $items[ $next + 2 ][2] ?? '' ) === $name && ';' === ( $items[ $next + 3 ][2] ?? '' ) ) {
			return array(
				'name' => (string) $items[ $next ][2],
				'at'   => $next + 3,
			);
		}
		return array(
			'name' => $name,
			'at'   => $semicolon,
		);
	}

	private static function evalModifier( string $literal ): bool {
		if ( strlen( $literal ) > 512 || ! preg_match( '/^[\'\"](.*)[\'\"]$/s', $literal, $match ) ) {
			return false;
		}
		return 1 === preg_match( '/^(.)(?:\\\\.|(?!\\1).)*\\1[A-Za-z]*e[A-Za-z]*$/s', $match[1] );
	}

	private static function request( array $items, int $index ): bool {
		return T_VARIABLE === ( $items[ $index ][1] ?? null ) && in_array( $items[ $index ][2], array( '$_GET', '$_POST', '$_REQUEST', '$_COOKIE' ), true ) && '[' === ( $items[ $index + 1 ][2] ?? '' ) && T_CONSTANT_ENCAPSED_STRING === ( $items[ $index + 2 ][1] ?? null ) && ']' === ( $items[ $index + 3 ][2] ?? '' );
	}

	/** Index of the matching ')' for an opening '(' token, or -1. */
	private static function balancedClose( array $items, int $open ): int {
		$depth = 0;
		$count = count( $items );
		for ( $k = $open; $k < $count; ++$k ) {
			$piece = $items[ $k ][2] ?? '';
			if ( '(' === $piece ) {
				++$depth;
			} elseif ( ')' === $piece ) {
				--$depth;
				if ( 0 === $depth ) {
					return $k;
				}
			}
		}
		return -1;
	}
}
