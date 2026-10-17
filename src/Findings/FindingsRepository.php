<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Findings;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Scan\ScanRun;
use RuntimeException;

final class FindingsRepository {
	private const OPTION = 'amazing_security_latest_run';

	public function save( ScanRun $run ): void {
		$value = wp_json_encode( $run->toArray() );
		if ( ! is_string( $value ) ) {
			throw new RuntimeException( 'Could not serialize scan run.' );
		}
		$previous = get_option( self::OPTION, false );
		if ( $previous === $value ) {
			return;
		}
		if ( false === $previous ) {
			if ( ! add_option( self::OPTION, $value, '', false ) ) {
				throw new RuntimeException( 'Could not save scan run.' );
			}
		} elseif ( ! update_option( self::OPTION, $value, false ) ) {
			throw new RuntimeException( 'Could not update scan run.' );
		}
	}

	public function latest(): ?ScanRun {
		$value = get_option( self::OPTION, false );
		if ( ! is_string( $value ) ) {
			return null;
		}
		try {
			$data = json_decode( $value, true, 512, JSON_THROW_ON_ERROR );
			return is_array( $data ) ? ScanRun::fromArray( $data ) : null;
		} catch ( \Throwable $error ) {
			return null;
		}
	}
}
