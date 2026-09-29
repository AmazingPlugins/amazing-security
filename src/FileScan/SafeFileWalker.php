<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\FileScan;

use AmazingPlugins\Security\Scan\ScanContext;
use Throwable;

final class SafeFileWalker {
	private array $listCache = array();

	/** @param FileScanTarget[] $targets */
	public function step( array $targets, FileScanCursor $cursor, ScanContext $context ): FileScanStep {
		$this->listCache = array();
		$started         = microtime( true );
		$items           = array();
		$limit           = min( 250, $context->entryLimit );
		$count           = 0;
		while ( $count < $limit && microtime( true ) < $context->deadline && microtime( true ) - $started < 5 ) {
			$item = $this->next( $targets, $cursor );
			if ( null === $item ) {
				break;
			}
			$items[] = $item;
			++$count;
		}
		$cursor->elapsed += microtime( true ) - $started;
		if ( $cursor->elapsed >= 30 || $cursor->processed >= 5000 ) {
			$cursor->partial  = true;
			$cursor->finished = true;
		}
		return new FileScanStep( $cursor, $cursor->finished, $items );
	}

	/** @param FileScanTarget[] $targets */
	public function next( array $targets, FileScanCursor $cursor ): ?array {
		$signature = $this->signature( $targets );
		if ( '' === $cursor->targetSignature ) {
			$cursor->targetSignature = $signature;
		} elseif ( ! hash_equals( $cursor->targetSignature, $signature ) ) {
			$cursor->partial  = true;
			$cursor->finished = true;
			++$cursor->unknown;
			return null;
		}
		if ( $cursor->finished || $cursor->processed >= 5000 || $cursor->bytes >= 134217728 || $cursor->elapsed >= 30 ) {
			$cursor->partial  = $cursor->partial || ! $cursor->finished;
			$cursor->finished = true;
			return null;
		}
		while ( isset( $targets[ $cursor->targetIndex ] ) ) {
			$target = $targets[ $cursor->targetIndex ];
			$root   = realpath( $target->root );
			if ( false === $root || is_link( $target->root ) || ! is_dir( $root ) ) {
				++$cursor->unknown;
				$cursor->partial = true;
				++$cursor->targetIndex;
				$cursor->stack = array();
				continue;
			}
			if ( array() === $cursor->stack ) {
				$cursor->stack[] = array(
					'path' => '',
					'last' => '',
					'hash' => '',
				);
			}
			$index     = count( $cursor->stack ) - 1;
			$frame     = $cursor->stack[ $index ];
			$directory = $root . ( '' === $frame['path'] ? '' : '/' . $frame['path'] );
			$resolved  = realpath( $directory );
			if ( false === $resolved || is_link( $directory ) || ( $resolved !== $root && ! str_starts_with( $resolved, $root . DIRECTORY_SEPARATOR ) ) ) {
				++$cursor->unknown;
				$cursor->partial = true;
				array_pop( $cursor->stack );
				continue;
			}
			$entries = $this->entries( $directory );
			if ( null === $entries ) {
				++$cursor->unknown;
				$cursor->partial = true;
				array_pop( $cursor->stack );
				continue;
			}
			$hash = hash( 'sha256', implode( "\0", $entries ) );
			if ( '' !== $frame['hash'] && ! hash_equals( $frame['hash'], $hash ) ) {
				++$cursor->unknown;
				$cursor->partial  = true;
				$cursor->finished = true;
				return null;
			}
			$cursor->stack[ $index ]['hash'] = $hash;
			$next                            = '' === $frame['last'] ? 0 : (int) array_search( $frame['last'], $entries, true ) + 1;
			if ( $next >= count( $entries ) ) {
				array_pop( $cursor->stack );
				if ( array() === $cursor->stack ) {
					++$cursor->targetIndex;
				}
				continue;
			}
			$name                            = $entries[ $next ];
			$cursor->stack[ $index ]['last'] = $name;
			$relative                        = '' === $frame['path'] ? $name : $frame['path'] . '/' . $name;
			if ( $this->excludedCorePath( $target, $relative ) ) {
				++$cursor->excluded;
				continue;
			}
			$path = $root . '/' . $relative;
			$stat = lstat( $path );
			if ( false === $stat || is_link( $path ) || ! in_array( $stat['mode'] & 0170000, array( 0040000, 0100000 ), true ) ) {
				++$cursor->unknown;
				$cursor->partial = true;
				continue;
			}
			$resolved = realpath( $path );
			if ( false === $resolved || ! str_starts_with( $resolved, $root . DIRECTORY_SEPARATOR ) ) {
				++$cursor->unknown;
				$cursor->partial = true;
				continue;
			}
			if ( 0040000 === ( $stat['mode'] & 0170000 ) ) {
				if ( count( $cursor->stack ) >= 32 ) {
					++$cursor->unknown;
					$cursor->partial = true;
					continue;
				}
					$cursor->stack[] = array(
						'path' => $relative,
						'last' => '',
						'hash' => '',
					);
					continue;
			}
			++$cursor->processed;
			$extra = null !== $target->manifest && ! isset( $target->manifest->files[ $relative ] );
			if ( $extra ) {
				++$cursor->extra;
			}
			return array(
				'target_index' => $cursor->targetIndex,
				'path'         => $relative,
				'extra'        => $extra,
				'size'         => (int) $stat['size'],
				'kind'         => $target->kind,
			);
		}
		$cursor->finished = true;
		return null;
	}

	private function entries( string $directory ): ?array {
		if ( isset( $this->listCache[ $directory ] ) ) {
			return $this->listCache[ $directory ];
		}
		try {
			$entries = array();
			foreach ( new \DirectoryIterator( $directory ) as $entry ) {
				if ( $entry->isDot() ) {
					continue;
				}
				if ( count( $entries ) >= 10000 ) {
					return null;
				}
				$entries[] = $entry->getFilename();
			}
			sort( $entries, SORT_STRING );
			$this->listCache[ $directory ] = $entries;
			return $entries;
		} catch ( Throwable $error ) {
			return null;
		}
	}

	private function excludedCorePath( FileScanTarget $target, string $relative ): bool {
		if ( 'core' !== $target->kind ) {
			return false;
		}
		if ( ! str_contains( $relative, '/' ) ) {
			return in_array( $relative, array( 'wp-config.php', 'wp-content', '.htaccess' ), true ) || ( is_dir( $target->root . '/' . $relative ) && ! in_array( $relative, array( 'wp-admin', 'wp-includes' ), true ) );
		}
		return ! str_starts_with( $relative, 'wp-admin/' ) && ! str_starts_with( $relative, 'wp-includes/' );
	}

	private function signature( array $targets ): string {
		$parts = array();
		foreach ( $targets as $target ) {
			$files = $target->manifest?->files ?? array();
			ksort( $files );
			// phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Pure deterministic fingerprint also runs outside WordPress.
			$parts[] = $target->identity . ':' . $target->kind . ':' . hash( 'sha256', $target->root ) . ':' . hash( 'sha256', json_encode( $files, JSON_THROW_ON_ERROR ) );
		}
		return hash( 'sha256', implode( '|', $parts ) );
	}
}
