<?php

declare(strict_types=1);

require dirname(__DIR__) . '/vendor/autoload.php';

if ( ! function_exists( 'esc_html' ) ) {
	function esc_html( string $value ): string { return htmlspecialchars( $value, ENT_QUOTES, 'UTF-8' ); }
	function esc_attr( string $value ): string { return htmlspecialchars( $value, ENT_QUOTES, 'UTF-8' ); }
	function esc_url( string $value ): string { return htmlspecialchars( $value, ENT_QUOTES, 'UTF-8' ); }
}
