<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Findings;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Scan\ScanRun;

/** Plain-text handoff. It leaves out evidence, addresses, and absolute paths. */
final class FindingsReport {
	public static function text( ?ScanRun $run ): string {
		$lines = array(
			__( 'AmSec Security Scanner findings', 'amsec-security-scanner' ),
			__( 'This is a starting list for the site owner or a host. It is not a compliance report. It does not show that the site is clean.', 'amsec-security-scanner' ),
			__( 'Login CAPTCHA and compromised-password checks stay on this site. No password or login attempt was sent.', 'amsec-security-scanner' ),
			'',
		);
		if ( null === $run ) {
			$lines[] = __( 'No completed local check is stored.', 'amsec-security-scanner' );
			return implode( "\n", $lines ) . "\n";
		}
		$lines[] = sprintf( /* translators: %s: time the completed local check finished, in ISO 8601 format. */ __( 'Checked: %s', 'amsec-security-scanner' ), $run->finishedAt->format( 'c' ) );
		$lines[] = $run->partial ? __( 'This check did not finish.', 'amsec-security-scanner' ) : __( 'This check finished.', 'amsec-security-scanner' );
		$lines[] = '';
		foreach ( $run->results as $result ) {
			if ( ! $result instanceof CheckResult ) {
				continue;
			}
			$lines[] = $result->checkId . ': ' . self::state( $result->state );
			$lines[] = self::redact( $result->summary );
			$lines[] = '';
		}
		return implode( "\n", $lines );
	}

	private static function state( string $state ): string {
		return match ( $state ) {
			'critical' => __( 'Critical', 'amsec-security-scanner' ),
			'fail' => __( 'Needs a change', 'amsec-security-scanner' ),
			'warn' => __( 'Needs attention', 'amsec-security-scanner' ),
			'pass' => __( 'Configured', 'amsec-security-scanner' ),
			'unknown' => __( 'Could not check', 'amsec-security-scanner' ),
			default => __( 'Could not check', 'amsec-security-scanner' ),
		};
	}

	private static function redact( string $text ): string {
		$withoutEmail = preg_replace( '/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i', '[email]', $text );
		$text         = is_string( $withoutEmail ) ? $withoutEmail : $text;
		$withoutPath  = preg_replace( '/(?:[A-Za-z]:\\\\|\/)[A-Za-z0-9._@\/\\\\-]{2,}/', '[path]', $text );
		return is_string( $withoutPath ) ? $withoutPath : $text;
	}
}
