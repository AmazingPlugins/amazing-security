<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Mcp;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Findings\CheckResult;

final class OutputProjector {
	public function check( string $module, CheckResult $result ): array {
		$key = $result->findingId ?? ( 'hardening' === $module ? $result->checkId : hash( 'sha256', $result->checkId . ':' . $result->sourceUrl . ':' . (string) ( $result->evidence['path'] ?? $result->evidence['slug'] ?? $result->evidence['package'] ?? '' ) ) );
		return array(
			'id'         => substr( hash( 'sha256', $module . ':' . $key ), 0, 32 ),
			'module'     => $module,
			'state'      => $result->state,
			'summary'    => $this->text( $result->summary, 500 ),
			'source_url' => $this->sourceUrl( $result->sourceUrl ),
			'tested_at'  => $result->testedAt->format( 'c' ),
			'confidence' => $result->confidence,
			'coverage'   => $result->coverage,
		);
	}

	public function file( array $result, bool $partial = false, bool $historical = false ): ?array {
		$id   = $result['id'] ?? null;
		$path = $result['path'] ?? null;
		if ( ! is_string( $id ) || ! preg_match( '/^[a-f0-9]{32}$/D', $id ) || ! is_string( $path ) || '' === $path || str_starts_with( $path, '/' ) || str_contains( $path, '\\' ) || str_contains( $path, '..' ) || strlen( $path ) > 500 ) {
			return null;
		}
		return array(
			'id'             => substr( hash( 'sha256', 'file:' . $id ), 0, 32 ),
			'module'         => 'file',
			'state'          => in_array( $result['state'] ?? '', array( 'warn', 'inconclusive', 'pass' ), true ) ? $result['state'] : 'inconclusive',
			'summary'        => $this->text( (string) ( $result['summary'] ?? '' ), 500 ),
			'path'           => $path,
			'package'        => $this->text( (string) ( $result['package'] ?? '' ), 120 ),
			'rule_id'        => $this->text( (string) ( $result['rule_id'] ?? '' ), 80 ),
			'line'           => max( 0, (int) ( $result['line'] ?? 0 ) ),
			'tested_at'      => $this->text( (string) ( $result['tested_at'] ?? '' ), 40 ),
			'confidence'     => 'low',
			'coverage'       => $partial ? 'partial' : 'complete',
			'historical'     => $historical,
			'current_status' => $historical ? 'unknown' : 'observed',
		);
	}

	private function text( string $value, int $limit ): string {
		$bounded = function_exists( 'mb_strcut' ) ? mb_strcut( $value, 0, $limit, 'UTF-8' ) : substr( $value, 0, $limit );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Pure PHP fallback replaces broken UTF-8 after byte truncation.
		return json_decode( json_encode( $bounded, JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR ), true, 512, JSON_THROW_ON_ERROR );
	}

	private function sourceUrl( string $value ): string {
		// phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url -- This projection is also exercised in pure PHP tests.
		$parts = parse_url( $value );
		if ( ! is_array( $parts ) || ! is_string( $parts['host'] ?? null ) ) {
			return '';
		}
		$port = isset( $parts['port'] ) ? ':' . (int) $parts['port'] : '';
		$path = is_string( $parts['path'] ?? null ) ? $parts['path'] : '';
		return $this->text( 'https://' . $parts['host'] . $port . $path, 500 );
	}
}
