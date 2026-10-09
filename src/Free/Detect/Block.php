<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Free\Detect;

/** Precise request block. It stays quiet unless the option is on. */
final class Block {
	/** @param array<mixed> $get */
	public static function hit( array $get, bool $enabled, bool $disabled ): bool {
		if ( ! $enabled || $disabled ) {
			return false;
		}
		$total = 0;
		foreach ( $get as $key => $value ) {
			if ( ! is_string( $key ) || ! is_string( $value ) ) {
				continue;
			}
			$total += strlen( $key ) + strlen( $value );
			if ( $total > 2048 ) {
				return false;
			}
			if ( 'amsec_block_probe' === $key || str_contains( $value, 'amsec_webshell_marker_<?php' ) ) {
				return true;
			}
		}
		return false;
	}
}
