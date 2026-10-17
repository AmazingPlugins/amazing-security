<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Findings;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Scan\ScanRun;

/** Plain-text handoff. It leaves out evidence, addresses, and absolute paths. */
final class FindingsReport {
	public static function text( ?ScanRun $run ): string {
		$lines = array(
			'Amazing Security findings',
			'This is a starting list for the site owner or a host. It is not a compliance report. It does not show that the site is clean.',
			'Login CAPTCHA and compromised-password checks stay on this site. No password or login attempt was sent.',
			'',
		);
		if ( null === $run ) {
			$lines[] = 'No completed local check is stored.';
			return implode( "\n", $lines ) . "\n";
		}
		$lines[] = 'Checked: ' . $run->finishedAt->format( 'c' );
		$lines[] = $run->partial ? 'This check did not finish.' : 'This check finished.';
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
			'critical' => 'Critical',
			'fail' => 'Needs a change',
			'warn' => 'Needs attention',
			'pass' => 'Configured',
			'unknown' => 'Could not check',
			default => 'Could not check',
		};
	}

	private static function redact( string $text ): string {
		$withoutEmail = preg_replace( '/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i', '[email]', $text );
		$text         = is_string( $withoutEmail ) ? $withoutEmail : $text;
		$withoutPath  = preg_replace( '/(?:[A-Za-z]:\\\\|\/)[A-Za-z0-9._@\/\\\\-]{2,}/', '[path]', $text );
		return is_string( $withoutPath ) ? $withoutPath : $text;
	}
}
