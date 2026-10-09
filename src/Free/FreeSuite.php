<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Free;

/** Loads each src/Free/<Name>/Module.php without a shared edit point. */
final class FreeSuite {
	public static function boot(): void {
		$paths = glob( __DIR__ . '/*/Module.php' );
		if ( ! is_array( $paths ) ) {
			return;
		}
		sort( $paths );
		foreach ( $paths as $path ) {
			$name = basename( dirname( $path ) );
			if ( 1 !== preg_match( '/^[A-Z][A-Za-z0-9]+$/', $name ) ) {
				continue;
			}
			$class = __NAMESPACE__ . '\\' . $name . '\\Module';
			if ( is_callable( array( $class, 'boot' ) ) ) {
				$class::boot();
			}
		}
	}
}
