<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Scan;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Content\WordPressContentService;
use AmazingPlugins\Security\Exposure\WordPressExposureService;
use Throwable;

/** Continues the local code, inventory, and content scans. It does not contact WordPress.org. */
final class LocalPass {
	public function advance(): string {
		$status = 'ok';
		foreach ( array( $this->code(), $this->inventory(), $this->content() ) as $part ) {
			if ( 'ok' !== $part ) {
				$status = $part;
			}
		}
		return $status;
	}

	/** @param float $seconds How long this batch may read files; the background tick picks up the rest. */
	public function code( float $seconds = 12 ): string {
		try {
			( new LocalCodeScan() )->advance( true, $seconds );
		} catch ( Throwable $error ) {
			return $error::class;
		}
		return 'ok';
	}

	public function inventory(): string {
		try {
			$inventory = ( new WordPressExposureService() )->create();
			foreach ( array( 'site', 'content', 'uploads' ) as $alias ) {
				$inventory->scan( $alias, time() );
			}
		} catch ( Throwable $error ) {
			return $error::class;
		}
		return 'ok';
	}

	public function content(): string {
		try {
			$content = ( new WordPressContentService() )->create();
			$state   = $content->status();
			if ( empty( $state['invalid'] ) && null === ( $state['active'] ?? null ) && null === ( $state['complete'] ?? null ) ) {
				$content->start( time() );
			}
			$deadline = microtime( true ) + 4;
			do {
				$result = $content->step( time() );
			} while ( 'progress' === $result && microtime( true ) < $deadline );
		} catch ( Throwable $error ) {
			return $error::class;
		}
		return 'ok';
	}
}
