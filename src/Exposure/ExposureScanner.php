<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Exposure;

use Closure;
use DirectoryIterator;

/** Selected filename inventory. Candidate files are never opened or read. */
final class ExposureScanner {
	private readonly Closure $clock;
	private readonly Closure $stat;
	public function __construct( ?callable $clock = null, ?callable $stat = null ) {
		$this->clock = Closure::fromCallable( $clock ?? static fn(): float=>microtime( true ) );
		$this->stat  = Closure::fromCallable(
			$stat ?? static function ( string $p ): ?array {
				clearstatcache( true, $p );
		// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Inaccessible metadata is explicitly unknown; no path warning is emitted.
				$s = @lstat( $p );
				return false === $s ? null : $s;
			}
		);
	}
	public function scan( ?string $root, string $alias, int $now ): array {
		$report    = array(
			'alias'       => $alias,
			'captured_at' => $now,
			'entries'     => 0,
			'directories' => 0,
			'unknown'     => 0,
			'excluded'    => 0,
			'partial'     => false,
			'reasons'     => array(),
			'candidates'  => array(),
		);
		$start     = ( $this->clock )();
		$root      = null === $root ? '' : rtrim( $root, '/' );
		$canonical = '' === $root ? false : realpath( $root );
		$stamp     = '' === $root ? null : ( $this->stat )( $root );
		if ( ! in_array( $alias, array( 'site', 'content', 'uploads' ), true ) || false === $canonical || '/' === $canonical || is_link( $root ) || ! is_array( $stamp ) || ( $stamp['mode'] & 0170000 ) !== 0040000 ) {
			$this->partial( $report, 'root_unavailable' );
			return $report;}
		$root       = $canonical;
		$stamp      = ( $this->stat )( $root );
		$queue      = array(
			array(
				'path'  => '',
				'depth' => 0,
			),
		);
		$depthLimit = 'uploads' === $alias ? 3 : 0;
		try {
			while ( array() !== $queue ) {
				if ( ( $this->clock )() - $start >= 5 ) {
					$this->partial( $report, 'work_target' );
					break;}
				if ( $report['directories'] >= 50 ) {
					$this->partial( $report, 'directory_limit' );
					break;}
				$dir    = array_shift( $queue );
				$path   = $root . ( '' === $dir['path'] ? '' : '/' . $dir['path'] );
				$before = ( $this->stat )( $path );
				if ( ! is_array( $before ) || ( $before['mode'] & 0170000 ) !== 0040000 || ! $this->contained( $path, $root ) ) {
					++$report['unknown'];
					$this->partial( $report, 'unknown_entries' );
					continue;}
				++$report['directories'];
				try {
					$iterator = new DirectoryIterator( $path );
				} catch ( \UnexpectedValueException ) {
					++$report['unknown'];
						$this->partial( $report, 'unknown_entries' );
						continue;}
				foreach ( $iterator as $entry ) {
					if ( $entry->isDot() ) {
						continue;}
					if ( ( $this->clock )() - $start >= 5 ) {
						$this->partial( $report, 'work_target' );
						break 2;}
					if ( $report['entries'] >= 1500 ) {
						$this->partial( $report, 'entry_limit' );
						break 2;}
					++$report['entries'];
					$relative = ( '' === $dir['path'] ? '' : $dir['path'] . '/' ) . $entry->getFilename();
					if ( ! self::validPath( $relative ) ) {
						++$report['unknown'];
						$this->partial( $report, 'unknown_entries' );
						continue;}
					$file = $root . '/' . $relative;
					$meta = ( $this->stat )( $file );
					if ( ! is_array( $meta ) || ! $this->contained( $file, $root ) ) {
						++$report['unknown'];
						$this->partial( $report, 'unknown_entries' );
						continue;}
					$type = $meta['mode'] & 0170000;
					if ( 0040000 === $type ) {
						if ( $dir['depth'] < $depthLimit ) {
							if ( count( $queue ) < 50 ) {
								$queue[] = array(
									'path'  => $relative,
									'depth' => $dir['depth'] + 1,
								);
							} else {
								++$report['excluded'];
								$this->partial( $report, 'directory_limit' );
							}
						} else {
							++$report['excluded'];
							if ( 'uploads' === $alias ) {
								$this->partial( $report, 'depth_limit' );
							}
						}continue;}
					if ( 0100000 !== $type || $meta['size'] < 0 || $meta['mtime'] < 0 ) {
						++$report['unknown'];
						$this->partial( $report, 'unknown_entries' );
						continue;}
					$category = self::classify( $entry->getFilename() );
					if ( null === $category ) {
									continue;}
					$after = ( $this->stat )( $file );
					if ( ! is_array( $after ) || ! $this->same( $meta, $after ) || ! $this->contained( $file, $root ) ) {
								++$report['unknown'];
											$this->partial( $report, 'unknown_entries' );
											continue;}
					if ( count( $report['candidates'] ) >= 100 ) {
						$this->partial( $report, 'candidate_limit' );
						break 2;}
					$report['candidates'][] = array(
						'alias'       => $alias,
						'path'        => $relative,
						'category'    => $category,
						'bytes'       => $meta['size'],
						'modified_at' => $meta['mtime'],
					);
				}
				$after = ( $this->stat )( $path );
				if ( ! is_array( $after ) || ! $this->same( $before, $after ) ) {
					++$report['unknown'];
							$this->partial( $report, 'unknown_entries' );}
			}
		} catch ( \Throwable ) {
			$this->partial( $report, 'unknown_entries' );
			++$report['unknown'];}
		$after = ( $this->stat )( $root );
		if ( ! is_array( $after ) || ! is_array( $stamp ) || ! $this->same( $stamp, $after ) || ! $this->contained( $root, $root ) ) {
			$report['candidates'] = array();
			$this->partial( $report, 'root_changed' );}
		return $report;
	}
	public static function validPath( string $path ): bool {
		return strlen( $path ) <= 300 && 1 === preg_match( '~^(?!/)(?!.*(?:^|/)\.\.?(/|$))[^\\\\\x00-\x1F\x7F]+$~uD', $path );}
	public static function classify( string $name ): ?string {
		$name = strtolower( $name );
		if ( in_array( $name, array( 'debug.log', 'error_log', 'error.log', 'php_errors.log' ), true ) ) {
			return 'log';}
		if ( preg_match( '/\.sql(?:\.(?:gz|zip|bz2))?$/D', $name ) ) {
			return 'database_dump';}
		if ( preg_match( '/^\.env(?:\.[a-z0-9_-]+)?$/D', $name ) || preg_match( '/^(?:wp-config\.php|\.htaccess|web\.config)(?:\.(?:bak|old|orig|save|backup)|~)$/D', $name ) ) {
			return 'configuration_leftover';}
		if ( preg_match( '/(?:\.(?:zip|tar|tgz|7z|rar|bak|old|orig|save|backup)|\.tar\.gz|~)$/D', $name ) ) {
			return 'archive_backup';}
		return null;
	}
	private function contained( string $path, string $root ): bool {
		clearstatcache( true, $path );
		$real = realpath( $path );
		return ! is_link( $path ) && false !== $real && $real === $path && ( $real === $root || str_starts_with( $real, $root . '/' ) );}
	private function same( array $a, array $b ): bool {
		$keys = array_flip( array( 'dev', 'ino', 'mode', 'size', 'mtime', 'ctime' ) );
		return array_intersect_key( $a, $keys ) === array_intersect_key( $b, $keys );}
	private function partial( array &$report, string $reason ): void {
		$report['partial'] = true;
		if ( ! in_array( $reason, $report['reasons'], true ) ) {
			$report['reasons'][] = $reason;}}
}
