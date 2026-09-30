<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Repository;

use DateTimeImmutable;
use DateTimeZone;

/** Normalizes selected official-directory fields; never retains response HTML. */
final class DirectoryRecord {
	public function unknown(): array {
		return array(
			'state'       => 'unknown',
			'version'     => '',
			'closed_date' => '',
			'reason'      => 'unknown',
			'updated_at'  => null,
			'old_update'  => false,
		);}
	public function parse( int $http, string $body, string $slug, int $now ): array {
		$result = $this->unknown();
		if ( strlen( $body ) > 65536 || ! in_array( $http, array( 200, 404 ), true ) ) {
			return $result;}
	 // phpcs:ignore WordPress.WP.AlternativeFunctions.json_decode_json_decode -- Pure bounded external-record normalization.
		$data = json_decode( $body, true );
		if ( ! is_array( $data ) || ( $data['slug'] ?? null ) !== $slug ) {
			return $result;}
		if ( true === ( $data['closed'] ?? null ) && 'closed' === ( $data['error'] ?? null ) ) {
			$result['state']       = 'closed';
			$reason                = $data['reason'] ?? null;
			$result['reason']      = is_string( $reason ) && in_array( $reason, array( 'security-issue', 'author-request', 'guideline-violation', 'licensing-trademark-violation', 'unused', 'unknown' ), true ) ? $reason : 'unknown';
			$date                  = $data['closed_date'] ?? null;
			$timestamp             = is_string( $date ) ? $this->date( $date, array( 'Y-m-d', 'Y-m-d H:i:s' ) ) : null;
			$result['closed_date'] = null !== $timestamp && $timestamp <= $now ? gmdate( 'Y-m-d', $timestamp ) : '';
			return $result;
		}
		if ( 200 !== $http || isset( $data['error'] ) || ( isset( $data['closed'] ) && false !== $data['closed'] ) || ! is_string( $data['version'] ?? null ) || strlen( $data['version'] ) > 64 || ! preg_match( '/^[0-9]+(?:\.[0-9]+)*(?:[-.][a-zA-Z0-9]+)*$/D', $data['version'] ) ) {
			return $result;}
		$result['state']   = 'listed';
		$result['version'] = $data['version'];
		$date              = $data['last_updated'] ?? null;
		$timestamp         = is_string( $date ) ? $this->date( $date, array( 'Y-m-d g:ia \G\M\T', 'Y-m-d h:ia \G\M\T', 'Y-m-d H:i:s', 'Y-m-d' ) ) : null;
		if ( null !== $timestamp && $timestamp <= $now ) {
			$result['updated_at'] = $timestamp;
			$result['old_update'] = $now - $timestamp > 730 * 86400;}
		return $result;
	}
	public function valid( array $record, int $checkedAt ): bool {
		if ( array_keys( $record ) !== array_keys( $this->unknown() ) || ! is_string( $record['state'] ) || ! is_string( $record['version'] ) || ! is_string( $record['reason'] ) || ! is_string( $record['closed_date'] ) || ! is_bool( $record['old_update'] ) || ( null !== $record['updated_at'] && ! is_int( $record['updated_at'] ) ) ) {
			return false;
		}
		if ( 'unknown' === $record['state'] ) {
			return $record === $this->unknown();
		}
		$data = array( 'slug' => 'validation' );
		if ( 'closed' === $record['state'] ) {
			$data += array(
				'error'       => 'closed',
				'closed'      => true,
				'closed_date' => $record['closed_date'],
				'reason'      => $record['reason'],
			);
		} elseif ( 'listed' === $record['state'] ) {
			$data += array(
				'version'      => $record['version'],
				'last_updated' => null === $record['updated_at'] ? '' : gmdate( 'Y-m-d H:i:s', $record['updated_at'] ),
			);
		} else {
			return false;
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Canonical pure-PHP validation of previously normalized fields.
		return $record === $this->parse( 200, json_encode( $data ), 'validation', $checkedAt );
	}

	private function date( string $value, array $formats ): ?int {
		if ( strlen( $value ) > 32 || ! preg_match( '/^[0-9a-zA-Z :\-]+$/D', $value ) ) {
			return null;}
		foreach ( $formats as $format ) {
			$date = DateTimeImmutable::createFromFormat( '!' . $format, $value, new DateTimeZone( 'UTC' ) );
			if ( false !== $date && $date->format( $format ) === $value ) {
				return $date->getTimestamp();}
		}
		return null;
	}
}
