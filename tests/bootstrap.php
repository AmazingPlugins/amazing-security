<?php

declare(strict_types=1);

require dirname(__DIR__) . '/vendor/autoload.php';

if ( ! function_exists( 'esc_html' ) ) {
	function esc_html( string $value ): string { return htmlspecialchars( $value, ENT_QUOTES, 'UTF-8' ); }
	function esc_attr( string $value ): string { return htmlspecialchars( $value, ENT_QUOTES, 'UTF-8' ); }
	function esc_url( string $value ): string { return htmlspecialchars( $value, ENT_QUOTES, 'UTF-8' ); }
}
if ( ! function_exists( '__' ) ) {
	function __( string $text, string $domain = 'default' ): string { return $text; }
	function esc_html__( string $text, string $domain = 'default' ): string { return htmlspecialchars( $text, ENT_QUOTES, 'UTF-8' ); }
	function esc_attr__( string $text, string $domain = 'default' ): string { return htmlspecialchars( $text, ENT_QUOTES, 'UTF-8' ); }
	function esc_html_e( string $text, string $domain = 'default' ): void { echo esc_html__( $text, $domain ); }
	function esc_attr_e( string $text, string $domain = 'default' ): void { echo esc_attr__( $text, $domain ); }
}
