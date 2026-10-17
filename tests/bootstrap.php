<?php

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', sys_get_temp_dir() . '/amsec-no-wordpress/' );
}

require dirname(__DIR__) . '/vendor/autoload.php';

if ( ! function_exists( 'esc_html' ) ) {
	function esc_html( string $value ): string { return htmlspecialchars( $value, ENT_QUOTES, 'UTF-8' ); }
	function esc_attr( string $value ): string { return htmlspecialchars( $value, ENT_QUOTES, 'UTF-8' ); }
	function esc_url( string $value ): string { return htmlspecialchars( $value, ENT_QUOTES, 'UTF-8' ); }
}
if ( ! function_exists( 'admin_url' ) ) {
	function admin_url( string $path = '' ): string {
		return 'http://example.test/wp-admin/' . ltrim( $path, '/' );
	}
	function add_query_arg( $args, string $url = '' ): string {
		return $url . '?' . http_build_query( is_array( $args ) ? $args : array() );
	}
}
if ( ! function_exists( 'wp_strip_all_tags' ) ) {
	function wp_strip_all_tags( string $text, bool $remove_breaks = false ): string {
		$clean = trim( strip_tags( $text ) );
		return $remove_breaks ? str_replace( array( "\r", "\n" ), '', $clean ) : $clean;
	}
}
if ( ! function_exists( '__' ) ) {
	function __( string $text, string $domain = 'default' ): string { return $text; }
	function _n( string $single, string $plural, int $number, string $domain = 'default' ): string { return 1 === $number ? $single : $plural; }
	function esc_html__( string $text, string $domain = 'default' ): string { return htmlspecialchars( $text, ENT_QUOTES, 'UTF-8' ); }
	function esc_attr__( string $text, string $domain = 'default' ): string { return htmlspecialchars( $text, ENT_QUOTES, 'UTF-8' ); }
	function esc_html_e( string $text, string $domain = 'default' ): void { echo esc_html__( $text, $domain ); }
	function esc_attr_e( string $text, string $domain = 'default' ): void { echo esc_attr__( $text, $domain ); }
}
