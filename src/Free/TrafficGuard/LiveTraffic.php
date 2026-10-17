<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Free\TrafficGuard;

defined( 'ABSPATH' ) || exit;

/** Local request rows: REMOTE_ADDR, path, and UTC time. */
final class LiveTraffic {
	public const CAP         = 500;
	public const VIEW        = 50;
	public const PATH_MAX    = 200;
	public const ADDRESS_MAX = 45;

	public function shouldStore( bool $enabled, array $server ): bool {
		if ( ! $enabled ) {
			return false;
		}
		if ( '1' === $this->serverString( $server, 'AMSEC_CLI' ) ) {
			return false;
		}
		if ( '1' === $this->serverString( $server, 'AMSEC_CRON' ) ) {
			return false;
		}
		if ( '1' === $this->serverString( $server, 'AMSEC_REST' ) ) {
			return false;
		}
		$uri    = $this->serverString( $server, 'REQUEST_URI' );
		$script = $this->serverString( $server, 'SCRIPT_NAME' );
		if ( $this->containsCron( $uri ) || $this->containsCron( $script ) ) {
			return false;
		}
		if ( $this->isWpAdmin( $uri, $script ) ) {
			return false;
		}
		if ( $this->isRestUri( $uri ) ) {
			return false;
		}
		return true;
	}

	/**
	 * @return array{ip: string, path: string, time: int}|null
	 */
	public function row( array $server, int $time ): ?array {
		$address = $this->address( $this->serverString( $server, 'REMOTE_ADDR' ) );
		if ( '' === $address ) {
			return null;
		}
		return array(
			'ip'   => $address,
			'path' => $this->path( $this->serverString( $server, 'REQUEST_URI' ) ),
			'time' => $time,
		);
	}

	public function path( string $uri ): string {
		$cut  = strcspn( $uri, '?#' );
		$path = substr( $uri, 0, $cut );
		$path = preg_replace( '/[^A-Za-z0-9\/_.\-]/', '', $path );
		if ( ! is_string( $path ) ) {
			return '';
		}
		if ( strlen( $path ) > self::PATH_MAX ) {
			return substr( $path, 0, self::PATH_MAX );
		}
		return $path;
	}

	public function address( string $remote ): string {
		$remote = trim( $remote );
		if ( '' === $remote || strlen( $remote ) > self::ADDRESS_MAX ) {
			return '';
		}
		if ( false === filter_var( $remote, FILTER_VALIDATE_IP ) ) {
			return '';
		}
		return $remote;
	}

	/**
	 * @param array<int, mixed>        $rows
	 * @param array<string, mixed>     $row
	 * @return list<array{ip: string, path: string, time: int}>
	 */
	public function append( array $rows, array $row ): array {
		$next = array();
		foreach ( $rows as $existing ) {
			$kept = $this->normalize( $existing );
			if ( null !== $kept ) {
				$next[] = $kept;
			}
		}
		$added = $this->normalize( $row );
		if ( null !== $added ) {
			$next[] = $added;
		}
		if ( count( $next ) > self::CAP ) {
			$next = array_values( array_slice( $next, -self::CAP ) );
		}
		return $next;
	}

	/**
	 * @param array<int, mixed> $rows
	 * @return list<array{ip: string, path: string, time: int}>
	 */
	public function latest( array $rows, int $count = self::VIEW ): array {
		$shown = array();
		foreach ( $rows as $row ) {
			$kept = $this->normalize( $row );
			if ( null !== $kept ) {
				$shown[] = $kept;
			}
		}
		$count = max( 0, $count );
		if ( count( $shown ) > $count ) {
			$shown = array_slice( $shown, -$count );
		}
		return array_reverse( $shown );
	}

	/**
	 * @return array{ip: string, path: string, time: int}|null
	 */
	private function normalize( mixed $row ): ?array {
		if ( ! is_array( $row ) ) {
			return null;
		}
		$ip   = $row['ip'] ?? '';
		$path = $row['path'] ?? '';
		$time = $row['time'] ?? null;
		if ( ! is_string( $ip ) || ! is_string( $path ) ) {
			return null;
		}
		if ( is_string( $time ) && ctype_digit( $time ) ) {
			$time = (int) $time;
		}
		if ( ! is_int( $time ) ) {
			return null;
		}
		if ( strlen( $ip ) > self::ADDRESS_MAX || strlen( $path ) > self::PATH_MAX ) {
			return null;
		}
		if ( str_contains( $path, '?' ) || preg_match( '/[^A-Za-z0-9\/_.\-]/', $path ) ) {
			return null;
		}
		return array(
			'ip'   => $ip,
			'path' => $path,
			'time' => $time,
		);
	}

	private function isWpAdmin( string $uri, string $script ): bool {
		$path = $this->path( $uri );
		if ( str_contains( $path, '/wp-admin/' ) || str_ends_with( $path, '/wp-admin' ) ) {
			return true;
		}
		return str_contains( $script, '/wp-admin/' );
	}

	private function containsCron( string $value ): bool {
		return str_contains( $value, 'wp-cron.php' );
	}

	private function isRestUri( string $uri ): bool {
		$path = $this->path( $uri );
		return str_contains( $path, '/wp-json/' ) || str_ends_with( $path, '/wp-json' );
	}

	private function serverString( array $server, string $key ): string {
		$value = $server[ $key ] ?? '';
		return is_string( $value ) ? $value : '';
	}
}
