<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Free\TrafficGuard;

defined( 'ABSPATH' ) || exit;

/** Exact host, exact browser, and referrer-prefix decisions. */
final class BlockList {
	public const MAX_ENTRIES = 20;
	public const MAX_LENGTH  = 120;

	public function blocked( string $hostnames, string $agents, string $referrers, array $server, bool $can_manage ): bool {
		if ( $can_manage ) {
			return false;
		}
		if ( '' === trim( $hostnames ) && '' === trim( $agents ) && '' === trim( $referrers ) ) {
			return false;
		}
		$host     = $this->serverString( $server, 'HTTP_HOST' );
		$agent    = $this->serverString( $server, 'HTTP_USER_AGENT' );
		$referrer = $this->serverString( $server, 'HTTP_REFERER' );
		if ( $this->hostMatches( $hostnames, $host ) ) {
			return true;
		}
		if ( $this->agentMatches( $agents, $agent ) ) {
			return true;
		}
		return $this->referrerMatches( $referrers, $referrer );
	}

	/**
	 * @return array{ok: bool, value: string, error: string}
	 */
	public function prepare( string $raw, string $kind, string $current ): array {
		if ( ! in_array( $kind, array( 'host', 'agent', 'referrer' ), true ) ) {
			return array(
				'ok'    => false,
				'value' => '',
				'error' => 'kind',
			);
		}
		$entries = $this->lines( $raw );
		if ( count( $entries ) > self::MAX_ENTRIES ) {
			return array(
				'ok'    => false,
				'value' => '',
				'error' => 'count',
			);
		}
		foreach ( $entries as $entry ) {
			$length = function_exists( 'mb_strlen' ) ? mb_strlen( $entry ) : strlen( $entry );
			if ( $length > self::MAX_LENGTH ) {
				return array(
					'ok'    => false,
					'value' => '',
					'error' => 'length',
				);
			}
			if ( 'referrer' === $kind && ! $this->isUrlPrefix( $entry ) ) {
				return array(
					'ok'    => false,
					'value' => '',
					'error' => 'prefix',
				);
			}
		}
		$value = implode( "\n", $entries );
		if ( $this->kindMatches( $kind, $value, $current ) ) {
			return array(
				'ok'    => false,
				'value' => '',
				'error' => 'self',
			);
		}
		return array(
			'ok'    => true,
			'value' => $value,
			'error' => '',
		);
	}

	/**
	 * @return list<string>
	 */
	public function lines( string $raw ): array {
		$parts = preg_split( "/\r\n|\n|\r/", $raw );
		if ( ! is_array( $parts ) ) {
			return array();
		}
		$lines = array();
		foreach ( $parts as $part ) {
			if ( ! is_string( $part ) ) {
				continue;
			}
			$part = trim( $part );
			if ( '' === $part ) {
				continue;
			}
			$lines[] = $part;
		}
		return $lines;
	}

	public function hostMatches( string $raw, string $host ): bool {
		$needle = $this->hostIdentity( $host );
		if ( '' === $needle || '' === trim( $raw ) ) {
			return false;
		}
		foreach ( $this->lines( $raw ) as $entry ) {
			if ( $this->hostIdentity( $entry ) === $needle ) {
				return true;
			}
		}
		return false;
	}

	public function agentMatches( string $raw, string $agent ): bool {
		if ( '' === $agent || '' === trim( $raw ) ) {
			return false;
		}
		foreach ( $this->lines( $raw ) as $entry ) {
			if ( $entry === $agent ) {
				return true;
			}
		}
		return false;
	}

	public function referrerMatches( string $raw, string $referrer ): bool {
		if ( '' === $referrer || '' === trim( $raw ) ) {
			return false;
		}
		foreach ( $this->lines( $raw ) as $entry ) {
			if ( $this->urlPrefixMatches( $entry, $referrer ) ) {
				return true;
			}
		}
		return false;
	}

	private function kindMatches( string $kind, string $raw, string $current ): bool {
		if ( 'host' === $kind ) {
			return $this->hostMatches( $raw, $current );
		}
		if ( 'agent' === $kind ) {
			return $this->agentMatches( $raw, $current );
		}
		return $this->referrerMatches( $raw, $current );
	}

	private function hostIdentity( string $host ): string {
		$host = strtolower( trim( $host ) );
		if ( '' === $host ) {
			return '';
		}
		if ( str_starts_with( $host, '[' ) && 1 === preg_match( '/\A(\[[0-9a-f:]+\])(?::\d{1,5})?\z/', $host, $matches ) ) {
			return $matches[1];
		}
		$stripped = preg_replace( '/:\d{1,5}\z/', '', $host );
		return is_string( $stripped ) ? $stripped : $host;
	}

	private function isUrlPrefix( string $entry ): bool {
		if ( 1 !== preg_match( '#\Ahttps?://#i', $entry ) ) {
			return false;
		}
		$parts = $this->parseUrl( $entry );
		$host  = $parts['host'] ?? '';
		return is_string( $host ) && '' !== $host;
	}

	private function urlPrefixMatches( string $entry, string $referrer ): bool {
		if ( ! $this->isUrlPrefix( $entry ) ) {
			return false;
		}
		$length = strlen( $entry );
		if ( strlen( $referrer ) < $length || 0 !== substr_compare( $referrer, $entry, 0, $length, true ) ) {
			return false;
		}
		if ( strlen( $referrer ) === $length || str_ends_with( $entry, '/' ) ) {
			return true;
		}
		$next = $referrer[ $length ];
		return '/' === $next || '?' === $next || '#' === $next;
	}

	/**
	 * @return array<string, mixed>
	 */
	private function parseUrl( string $url ): array {
		if ( function_exists( 'wp_parse_url' ) ) {
			$parts = wp_parse_url( $url );
			return is_array( $parts ) ? $parts : array();
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url -- Unit tests call this without WordPress loaded.
		$parts = parse_url( $url );
		return is_array( $parts ) ? $parts : array();
	}

	private function serverString( array $server, string $key ): string {
		$value = $server[ $key ] ?? '';
		return is_string( $value ) ? $value : '';
	}
}
