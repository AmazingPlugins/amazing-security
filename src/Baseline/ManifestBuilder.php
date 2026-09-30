<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Baseline;

use AmazingPlugins\Security\FileScan\BoundedContentReader;
use AmazingPlugins\Security\Integrity\IntegrityBudget;
use AmazingPlugins\Security\Integrity\WordPressOrgManifestProvider;

final class ManifestBuilder {
	public const EXTENSIONS = array( 'php', 'phtml', 'inc', 'js', 'css', 'html', 'htm', 'svg', 'json', 'twig' );

	public function collect( string $root, ?string $singleFile = null ): BaselineManifest {
		$root    = rtrim( $root, '/' );
		$started = microtime( true );
		$this->stat( $root, true );
		$budget       = new IntegrityBudget( 300, 16777216, 5, 5 );
		$reader       = new BoundedContentReader();
		$stack        = array( '' );
		$files        = array();
		$observations = array();
		$directories  = array();
		$entries      = 0;
		while ( array() !== $stack ) {
			$relative  = array_pop( $stack );
			$directory = $root . ( '' === $relative ? '' : '/' . $relative );
			if ( ! $budget->hasTime() || count( $stack ) > 1000 || substr_count( $relative, '/' ) > 30 ) {
				throw new \RuntimeException( 'Traversal incomplete.' );
			}
			$stat                      = $this->stat( $directory, true );
			$names                     = null !== $singleFile ? array( $singleFile ) : $this->names( $directory, $budget, $entries );
			$directories[ $directory ] = array( $stat['dev'], $stat['ino'], null === $singleFile ? $names : null );
			foreach ( $names as $name ) {
				$path = '' === $relative ? $name : $relative . '/' . $name;
				if ( ! $budget->hasTime() || ! WordPressOrgManifestProvider::safePath( $path ) || strlen( $path ) > 512 || ( null !== $singleFile && str_contains( $name, '/' ) ) ) {
					throw new \RuntimeException( 'Traversal budget or path refused.' );
				}
				$absolute = $root . '/' . $path;
				$stat     = $this->stat( $absolute );
				if ( 0040000 === ( $stat['mode'] & 0170000 ) ) {
					if ( null !== $singleFile ) {
						throw new \RuntimeException( 'Selected file changed type.' );
					}
					$stack[] = $path;
					continue;
				}
				if ( ! in_array( strtolower( pathinfo( $path, PATHINFO_EXTENSION ) ), self::EXTENSIONS, true ) ) {
					continue;
				}
				$result = $reader->read( $root, $path, $budget );
				if ( 'ok' !== $result->state || $this->identity( $stat ) !== $this->identity( $this->stat( $absolute ) ) ) {
					throw new \RuntimeException( 'Source read incomplete or changed.' );
				}
				$files[ $path ]        = $result->sha256;
				$observations[ $path ] = $this->identity( $stat );
			}
		}
		// Re-read covered files, including same-size/same-second writes; both passes share the five-second wall budget.
		$verify = new IntegrityBudget( 300, 16777216, max( 0.0, 5.0 - ( microtime( true ) - $started ) ), 5 );
		foreach ( $files as $path => $hash ) {
			$result = $reader->read( $root, $path, $verify );
			if ( 'ok' !== $result->state || ! hash_equals( $hash, $result->sha256 ) || $observations[ $path ] !== $this->identity( $this->stat( $root . '/' . $path ) ) ) {
				throw new \RuntimeException( 'Source changed during collection.' );
			}
		}
		foreach ( $directories as $directory => $snapshot ) {
			$stat = $this->stat( $directory, true );
			if ( $snapshot[0] !== $stat['dev'] || $snapshot[1] !== $stat['ino'] || ( null !== $snapshot[2] && $snapshot[2] !== $this->names( $directory, $verify, $entries, 3000 ) ) || ! $verify->hasTime() ) {
				throw new \RuntimeException( 'Directory changed during collection.' );
			}
		}
		foreach ( $observations as $path => $identity ) {
			if ( ! $verify->hasTime() || $identity !== $this->identity( $this->stat( $root . '/' . $path ) ) ) {
				throw new \RuntimeException( 'Source identity changed during verification.' );
			}
		}
		return new BaselineManifest( $files );
	}

	private function names( string $directory, IntegrityBudget $budget, int &$entries, int $limit = 1500 ): array {
		try {
			$names = array();
			foreach ( new \DirectoryIterator( $directory ) as $entry ) {
				if ( $entry->isDot() ) {
					continue;
				}
				if ( ++$entries > $limit || ! $budget->hasTime() ) {
					throw new \RuntimeException( 'Entry budget exceeded.' );
				}
				$names[] = $entry->getFilename();
			}
			sort( $names, SORT_STRING );
			return $names;
		} catch ( \Throwable ) {
			throw new \RuntimeException( 'Directory unavailable or traversal incomplete.' );
		}
	}

	private function stat( string $path, bool $directory = false ): array {
		clearstatcache( true, $path );
		// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- A raced/inaccessible target refuses the entire collection without host-path warnings.
		$stat = @lstat( $path );
		if ( ! is_array( $stat ) || is_link( $path ) || realpath( $path ) !== $path || ! in_array( $stat['mode'] & 0170000, $directory ? array( 0040000 ) : array( 0040000, 0100000 ), true ) ) {
			throw new \RuntimeException( 'Unsafe or unavailable entry.' );
		}
		return $stat;
	}

	private function identity( array $stat ): array {
		return array( $stat['dev'], $stat['ino'], $stat['mode'], $stat['size'], $stat['mtime'], $stat['ctime'] );
	}
}
