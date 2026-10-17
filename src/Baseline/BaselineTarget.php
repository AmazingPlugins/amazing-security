<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Baseline;

defined( 'ABSPATH' ) || exit;

final class BaselineTarget {
	public function __construct( public readonly string $kind, public readonly string $identity, public readonly string $root, public readonly ?string $singleFile = null ) {}

	public function key(): string {
		return $this->kind . ':' . $this->identity;
	}

	public function stamp(): string {
		clearstatcache( true, $this->root );
		// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Root identity failure refuses comparison.
		$stat = @lstat( $this->root );
		if ( ! is_array( $stat ) || realpath( $this->root ) !== $this->root || is_link( $this->root ) || 0040000 !== ( $stat['mode'] & 0170000 ) ) {
			throw new \RuntimeException( 'Target root changed or unavailable.' );
		}
		return hash( 'sha256', $this->root . ':' . $stat['dev'] . ':' . $stat['ino'] );
	}
}
