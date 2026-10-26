<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Digest;

defined( 'ABSPATH' ) || exit;

final class DigestSummary {
	public const SOURCES = array( 'hardening', 'integrity', 'files', 'vulnerabilities' );

	public static function build( array $sources, array $activity, ?array $previous, int $now ): array {
		$lines    = array( 'Amazing Security Scanner weekly digest', 'Generated UTC: ' . gmdate( 'Y-m-d H:i:s', $now ), null === $previous ? 'Initial snapshot; no earlier accepted digest for comparison.' : 'Newly observed findings compare with the last accepted digest.', '' );
		$snapshot = array(
			'identities' => array(),
			'capped'     => array(),
		);
		foreach ( self::SOURCES as $kind ) {
			$source     = is_array( $sources[ $kind ] ?? null ) ? $sources[ $kind ] : array();
			$at         = is_int( $source['at'] ?? null ) ? $source['at'] : 0;
			$missing    = $at < 1;
			$stale      = ! $missing && ( $at < $now - 604800 || $at > $now + 300 );
			$rows       = is_array( $source['rows'] ?? null ) ? $source['rows'] : array();
			$partial    = $missing || $stale || ! empty( $source['partial'] ) || ! empty( $source['running'] ) || count( $rows ) > 250;
			$unknown    = max( 0, min( 100000, (int) ( $source['unknown'] ?? 0 ) ) );
			$ids        = array();
			$rowUnknown = 0;
			foreach ( array_slice( $rows, 0, 250 ) as $row ) {
				if ( ! is_array( $row ) ) {
					$partial = true;
					++$rowUnknown;
					continue;
				}
				if ( ! in_array( $row['state'] ?? '', array( 'pass', 'warn', 'critical', 'fail' ), true ) ) {
					++$rowUnknown;
					$partial = true;
				}
				if ( 'complete' !== ( $row['coverage'] ?? 'complete' ) ) {
					$partial = true;
				}
				if ( in_array( $row['state'] ?? '', array( 'warn', 'critical', 'fail' ), true ) ) {
					$id = $row['id'] ?? null;
					if ( ! is_string( $id ) || '' === $id || strlen( $id ) > 1024 ) {
						$partial = true;
						++$rowUnknown;
						continue;
					}
					$ids[] = hash( 'sha256', $kind . ':' . $id );
				}
			}
			$unknown                         = max( $unknown, $rowUnknown );
			$ids                             = array_values( array_unique( $ids ) );
			$old                             = self::identities( $previous['identities'][ $kind ] ?? array() );
			$capped                          = ! empty( $previous['capped'][ $kind ] );
			$new                             = count( array_diff( $ids, $old ) );
			$retained                        = $partial ? array_values( array_unique( array_merge( $old, $ids ) ) ) : $ids;
			$snapshot['identities'][ $kind ] = array_slice( $retained, 0, 1000 );
			$snapshot['capped'][ $kind ]     = ( $partial && $capped ) || count( $retained ) > 1000;
			$coverage                        = $missing ? 'missing' : ( $stale ? 'stale' : ( $partial ? 'partial' : 'latest stored report' ) );
			$newText                         = null === $previous ? 'initial' : ( $capped ? 'new comparison unavailable: retained identity budget reached' : $new . ' newly observed' );
			$lines[]                         = ucfirst( $kind ) . ': ' . count( $ids ) . ' findings requiring review; ' . $newText . '; coverage ' . $coverage . '; ' . $unknown . ' unknown checks/items' . ( ! empty( $source['running'] ) ? '; unfinished scan' : '' ) . '.';
			if ( 'vulnerabilities' === $kind ) {
				$risk    = array_count_values( array_filter( array_map( static fn ( $row ): string => is_array( $row ) && is_string( $row['risk'] ?? null ) ? $row['risk'] : '', array_slice( $rows, 0, 250 ) ) ) );
				$lines[] = 'Package risk: ' . ( $risk['high'] ?? 0 ) . ' findings on high-risk packages; ' . ( $risk['watch'] ?? 0 ) . ' packages to watch (3 or more high-severity holes in 2 years).';
			}
		}
		$lines[] = '';
		$lines[] = ! empty( $activity['available'] ) ? 'Last seven days: ' . max( 0, min( 10000, (int) ( $activity['changes'] ?? 0 ) ) ) . ' recorded account/role change events; ' . max( 0, min( 10000, (int) ( $activity['blocked'] ?? 0 ) ) ) . ' recorded blocked login requests.' : 'Last seven days: activity counts unavailable.';
		$lines[] = 'Activity is bounded and can omit events. Counts are events, not unique administrators or all attacks.';
		$lines[] = 'This summary does not run scans or establish that the site is malware-free. Review scan timestamps, scope and unknown findings in WordPress.';
		return array(
			'body'     => implode( "\n", $lines ),
			'snapshot' => $snapshot,
		);
	}

	public static function identities( mixed $raw ): array {
		return is_array( $raw ) ? array_values( array_unique( array_filter( array_slice( $raw, 0, 1000 ), static fn( mixed $id ): bool => is_string( $id ) && (bool) preg_match( '/^[a-f0-9]{64}$/D', $id ) ) ) ) : array();
	}
}
