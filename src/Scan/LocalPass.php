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
		try {
			( new LocalCodeScan() )->advance();
		} catch ( Throwable $error ) {
			$status = $error::class;
		}
		try {
			$inventory = ( new WordPressExposureService() )->create();
			foreach ( array( 'site', 'content', 'uploads' ) as $alias ) {
				$inventory->scan( $alias, time() );
			}
		} catch ( Throwable $error ) {
			$status = $error::class;
		}
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
			$status = $error::class;
		}
		return $status;
	}
}
