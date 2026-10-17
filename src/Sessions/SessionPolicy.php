<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Sessions;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Access;

final class SessionPolicy {
	public static function matchingTokens( string $adminToken, string $loginToken ): bool {
		return '' !== $adminToken && hash_equals( $adminToken, $loginToken );
	}

	public static function allowed( bool $post, bool $administrator, bool $editable, bool $cookie, bool $secure, bool $confirmed ): bool {
		return $post && $administrator && $editable && $cookie && $secure && $confirmed;
	}

	public static function canView( bool $administrator, int $viewer, int $subject ): bool {
		return Access::session( $administrator, $viewer, $subject );
	}

	public static function safeRows( array $sessions, array $current = array() ): array {
		$rows = array();
		foreach ( $sessions as $session ) {
			if ( ! is_array( $session ) || ! isset( $session['login'], $session['expiration'] ) ) {
				continue;
			}
			$row            = array(
				'login'      => max( 0, (int) $session['login'] ),
				'expiration' => max( 0, (int) $session['expiration'] ),
				'ip'         => self::address( $session['ip'] ?? '' ),
				'ua'         => self::agent( $session['ua'] ?? '' ),
				'current'    => false,
			);
			$row['current'] = self::sameSession( $row, $current );
			$rows[]         = $row;
		}
		usort(
			$rows,
			static function ( array $left, array $right ): int {
				if ( $left['current'] !== $right['current'] ) {
					return $left['current'] ? -1 : 1;
				}
				return $right['login'] <=> $left['login'];
			}
		);
		$rows = array_slice( $rows, 0, 50 );
		$seen = false;
		foreach ( $rows as $index => $row ) {
			if ( ! $row['current'] ) {
				continue;
			}
			if ( $seen ) {
				$rows[ $index ]['current'] = false;
				continue;
			}
			$seen = true;
		}
		return $rows;
	}

	public static function ref( array $row ): string {
		return substr( hash( 'sha256', $row['login'] . '|' . $row['expiration'] . '|' . $row['ip'] . '|' . $row['ua'] ), 0, 16 );
	}

	/** @param array<int, array{login: int, expiration: int, ip: string, ua: string, current: bool}> $rows */
	public static function rowFor( array $rows, string $ref ): ?array {
		if ( 1 !== preg_match( '/\A[a-f0-9]{16}\z/', $ref ) ) {
			return null;
		}
		foreach ( $rows as $row ) {
			$expected = self::ref( $row );
			if ( strlen( $expected ) === strlen( $ref ) && hash_equals( $expected, $ref ) ) {
				return $row;
			}
		}
		return null;
	}

	private static function sameSession( array $row, array $current ): bool {
		if ( ! isset( $current['login'], $current['expiration'] ) ) {
			return false;
		}
		return max( 0, (int) $current['login'] ) === $row['login']
			&& max( 0, (int) $current['expiration'] ) === $row['expiration']
			&& self::address( $current['ip'] ?? '' ) === $row['ip']
			&& self::agent( $current['ua'] ?? '' ) === $row['ua'];
	}

	private static function address( mixed $ip ): string {
		if ( ! is_string( $ip ) || ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return '';
		}
		return $ip;
	}

	private static function agent( mixed $agent ): string {
		if ( ! is_string( $agent ) ) {
			return '';
		}
		$agent = trim( str_replace( array( "\r", "\n" ), ' ', wp_strip_all_tags( $agent ) ) );
		if ( strlen( $agent ) > 300 ) {
			$agent = substr( $agent, 0, 300 );
		}
		return $agent;
	}
}
