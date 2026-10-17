<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Traffic;

defined( 'ABSPATH' ) || exit;

final class TrafficEvent {
	public const METHODS    = array( 'GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'OTHER' );
	public const CATEGORIES = array( 'login', 'xmlrpc', 'admin', 'frontend', 'core-rest', 'store-rest', 'form-rest', 'other-rest', 'other' );
	public const DECISIONS  = array( 'unclassified', 'network-block', 'rest-rate-block' );
	private function __construct( private readonly array $fields ) {}
	public static function capture( array $server, ?string $route, int $status, string $decision, int $now ): self {
		$method   = is_string( $server['REQUEST_METHOD'] ?? null ) && strlen( $server['REQUEST_METHOD'] ) <= 16 ? strtoupper( $server['REQUEST_METHOD'] ) : 'OTHER';
		$category = 'other';
		if ( null !== $route ) {
			$category = 'other-rest';
			if ( strlen( $route ) <= 2048 ) {
				foreach ( array(
					'core-rest'  => '~^/wp/v2(?:/|$)~i',
					'store-rest' => '~^/wc(?:/|$)~i',
					'form-rest'  => '~^/contact-form-7(?:/|$)~i',
				) as $label => $pattern ) {
					if ( 1 === preg_match( $pattern, $route ) ) {
								$category = $label;
								break; }
				}
			}
		} elseif ( is_string( $server['SCRIPT_NAME'] ?? null ) && strlen( $server['SCRIPT_NAME'] ) <= 2048 ) {
			$script = $server['SCRIPT_NAME'];
			if ( 1 === preg_match( '~(?:^|/)wp-login\.php$~iD', $script ) ) {
				$category = 'login'; } elseif ( 1 === preg_match( '~(?:^|/)xmlrpc\.php$~iD', $script ) ) {
							$category = 'xmlrpc'; } elseif ( 1 === preg_match( '~(?:^|/)wp-admin/~i', $script ) ) {
							$category = 'admin'; } elseif ( 1 === preg_match( '~(?:^|/)index\.php$~iD', $script ) ) {
								$category = 'frontend'; }
		}
		return new self(
			array(
				'created_at' => max( 1, $now ),
				'method'     => in_array( $method, self::METHODS, true ) ? $method : 'OTHER',
				'category'   => $category,
				'status'     => $status >= 100 && $status <= 599 ? $status : 0,
				'decision'   => in_array( $decision, self::DECISIONS, true ) ? $decision : 'unclassified',
			)
		);
	}
	public function row(): array {
		return $this->fields; }
}
