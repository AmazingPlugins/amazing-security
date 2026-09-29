<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Vulnerabilities;

final class VersionRangeMatcher {
	public function contains( string $installed, array $range ): ?bool {
		if ( ! $this->validVersion( $installed ) || ! isset( $range['from'], $range['to'], $range['from_inclusive'], $range['to_inclusive'] ) || ! is_string( $range['from'] ) || ! is_string( $range['to'] ) || ! is_bool( $range['from_inclusive'] ) || ! is_bool( $range['to_inclusive'] ) ) {
			return null;
		}
		$from = $range['from'];
		$to   = $range['to'];
		if ( ( '*' !== $from && ! $this->validVersion( $from ) ) || ( '*' !== $to && ! $this->validVersion( $to ) ) || ( '*' !== $from && '*' !== $to && version_compare( $from, $to, '>' ) ) ) {
			return null;
		}
		if ( '*' !== $from ) {
			$comparison = version_compare( $installed, $from );
			if ( $comparison < 0 || ( 0 === $comparison && ! $range['from_inclusive'] ) ) {
				return false;
			}
		}
		if ( '*' !== $to ) {
			$comparison = version_compare( $installed, $to );
			if ( $comparison > 0 || ( 0 === $comparison && ! $range['to_inclusive'] ) ) {
				return false;
			}
		}
		return true;
	}

	private function validVersion( string $version ): bool {
		return strlen( $version ) <= 64 && 1 === preg_match( '/^\d+(?:\.\d+)*(?:[-.](?:alpha|beta|RC)\d*)?$/iD', $version );
	}
}
