<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Vulnerabilities;

use DateTimeImmutable;
use Throwable;

final class SnapshotVerifier {
	private const MAX_BYTES   = 2097152;
	private const MAX_RECORDS = 2000;

	/** @param array<string,string> $keys */
	public function __construct( private readonly array $keys = array(), private readonly ?DateTimeImmutable $now = null ) {}

	/** @param InstalledSoftware[] $inventory */
	public function inventoryHash( array $inventory ): string {
		$rows = array();
		foreach ( $inventory as $item ) {
			$rows[] = array( $item->type, $item->slug, $item->version );
		}
		sort( $rows );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Canonical pure-PHP signed snapshot contract.
		return hash( 'sha256', json_encode( $rows, JSON_THROW_ON_ERROR ) );
	}

	/** @param InstalledSoftware[] $inventory */
	public function verify( string $envelope, array $inventory, ?Snapshot $previous ): SnapshotResult {
		if ( strlen( $envelope ) > self::MAX_BYTES || ! function_exists( 'openssl_verify' ) ) {
			return $this->unknown( 'Envelope too large or signature verification unavailable.' );
		}
		try {
			$data = json_decode( $envelope, true, 32, JSON_THROW_ON_ERROR );
			if ( ! is_array( $data ) || ! $this->exactKeys( $data, array( 'key_id', 'payload_b64', 'signature_b64' ) ) || ! is_string( $data['key_id'] ) || ! is_string( $data['payload_b64'] ) || ! is_string( $data['signature_b64'] ) ) {
				return $this->unknown( 'Invalid snapshot envelope.' );
			}
			$key = $this->keys[ $data['key_id'] ] ?? null;
			// Base64 carries signed bytes in JSON; decoded PHP is never executed.
			// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
			$bytes = base64_decode( $data['payload_b64'], true );
			// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
			$signature = base64_decode( $data['signature_b64'], true );
			if ( ! is_string( $key ) || false === $bytes || false === $signature || strlen( $bytes ) > self::MAX_BYTES || 1 !== openssl_verify( $bytes, $signature, $key, OPENSSL_ALGO_SHA256 ) ) {
				return $this->unknown( 'Snapshot signature not trusted.' );
			}
			$payload = json_decode( $bytes, true, 32, JSON_THROW_ON_ERROR );
			if ( ! $this->validPayload( $payload, $inventory, $previous ) ) {
				return $this->unknown( 'Snapshot is stale, incomplete, or invalid for this inventory.' );
			}
			return new SnapshotResult( 'accepted', '', new Snapshot( $payload['sequence'], $payload['generated_at'], $payload['expires_at'], $payload['inventory_hash'], $payload['records'] ) );
		} catch ( Throwable $error ) {
			return $this->unknown( 'Snapshot could not be decoded.' );
		}
	}

	private function validPayload( mixed $payload, array $inventory, ?Snapshot $previous ): bool {
		if ( ! is_array( $payload ) || ! $this->exactKeys( $payload, array( 'schema', 'sequence', 'generated_at', 'expires_at', 'provider', 'inventory_hash', 'complete', 'records' ) ) ) {
			return false;
		}
		if ( 1 !== $payload['schema'] || ! is_int( $payload['sequence'] ) || $payload['sequence'] < 1 || ( null !== $previous && $payload['sequence'] <= $previous->sequence ) || 'wordfence-v3-production' !== $payload['provider'] || true !== $payload['complete'] || ! is_string( $payload['inventory_hash'] ) || ! hash_equals( $this->inventoryHash( $inventory ), $payload['inventory_hash'] ) || ! is_array( $payload['records'] ) || ! array_is_list( $payload['records'] ) || count( $payload['records'] ) > self::MAX_RECORDS ) {
			return false;
		}
		$generated = $this->date( $payload['generated_at'] );
		$expires   = $this->date( $payload['expires_at'] );
		$now       = $this->now ?? new DateTimeImmutable( 'now' );
		if ( null === $generated || null === $expires || $generated > $now->modify( '+5 minutes' ) || $generated < $now->modify( '-48 hours' ) || $expires <= $now || $expires > $generated->modify( '+48 hours' ) ) {
			return false;
		}
		foreach ( $payload['records'] as $record ) {
			if ( ! $this->validRecord( $record ) ) {
				return false;
			}
		}
		return true;
	}

	private function validRecord( mixed $record ): bool {
		if ( ! is_array( $record ) || ! isset( $record['id'], $record['title'], $record['software'], $record['affected'], $record['patched_versions'], $record['url'], $record['published_at'], $record['updated_at'], $record['copyrights'] ) || ! is_string( $record['id'] ) || ! preg_match( '/^[a-f0-9-]{36}$/iD', $record['id'] ) || ! is_string( $record['title'] ) || strlen( $record['title'] ) > 500 || ! is_array( $record['software'] ) || ! in_array( $record['software']['type'] ?? null, array( 'core', 'plugin', 'theme' ), true ) || ! is_string( $record['software']['slug'] ?? null ) || ! preg_match( '/^[a-z0-9-]+$/D', $record['software']['slug'] ) || ! is_array( $record['affected'] ) || ! array_is_list( $record['affected'] ) || count( $record['affected'] ) > 20 || ! is_array( $record['patched_versions'] ) || ! array_is_list( $record['patched_versions'] ) || ! is_string( $record['url'] ) || ! $this->providerUrl( $record['url'] ) || null === $this->date( $record['published_at'] ) || null === $this->date( $record['updated_at'] ) || ! is_array( $record['copyrights'] ) ) {
			return false;
		}
		foreach ( $record['affected'] as $range ) {
			if ( ! is_array( $range ) || ! isset( $range['from'], $range['to'], $range['from_inclusive'], $range['to_inclusive'] ) || ! is_string( $range['from'] ) || ! is_string( $range['to'] ) || ! is_bool( $range['from_inclusive'] ) || ! is_bool( $range['to_inclusive'] ) ) {
				return false;
			}
		}
		foreach ( $record['patched_versions'] as $version ) {
			if ( ! is_string( $version ) || strlen( $version ) > 64 ) {
				return false;
			}
		}
		return true;
	}

	private function providerUrl( string $url ): bool {
		// phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url -- Pure snapshot validation.
		return filter_var( $url, FILTER_VALIDATE_URL ) && 'https' === parse_url( $url, PHP_URL_SCHEME ) && 'www.wordfence.com' === parse_url( $url, PHP_URL_HOST );
	}

	private function date( mixed $value ): ?DateTimeImmutable {
		if ( ! is_string( $value ) || ! preg_match( '/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/D', $value ) ) {
			return null;
		}
		$date = DateTimeImmutable::createFromFormat( '!Y-m-d\TH:i:s\Z', $value, new \DateTimeZone( 'UTC' ) );
		return false !== $date && $date->format( 'Y-m-d\TH:i:s\Z' ) === $value ? $date : null;
	}

	private function unknown( string $reason ): SnapshotResult {
		return new SnapshotResult( 'unknown', $reason );
	}

	private function exactKeys( array $value, array $expected ): bool {
		$keys = array_keys( $value );
		sort( $keys );
		sort( $expected );
		return $keys === $expected;
	}
}
