<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Hardening;

use Closure;

/** Hides the generator tag and two discovery links when the owner turns them on. */
final class PublicMeta {
	private readonly Closure $generator;
	private readonly Closure $discovery;

	public function __construct( callable $generator, callable $discovery ) {
		$this->generator = Closure::fromCallable( $generator );
		$this->discovery = Closure::fromCallable( $discovery );
	}

	public function generator( mixed $html ): string {
		if ( ( $this->generator )() ) {
			return '';
		}
		return is_string( $html ) ? $html : '';
	}

	public function discovery(): void {
		if ( ! ( $this->discovery )() ) {
			return;
		}
		remove_action( 'wp_head', 'rsd_link' );
		remove_action( 'wp_head', 'wlwmanifest_link' );
	}
}
