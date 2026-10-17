<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Repository;

defined( 'ABSPATH' ) || exit;

final class WordPressDirectoryInventory {
	public function all(): array {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';}
		$rows = array();
		foreach ( get_plugins() as $file => $data ) {
			if ( count( $rows ) >= 100 ) {
				break;
			}$rows[] = $this->item( (string) $file, $data );}
		return $rows;
	}
	public function find( string $key ): ?array {
		foreach ( $this->all() as $item ) {
			if ( $item['key'] === $key ) {
				$file = $item['file'];
				$path = WP_PLUGIN_DIR . '/' . $file;
				if ( ! $this->regular( $path ) ) {
					return null;
				}return $this->item( $file, get_plugin_data( $path, false, false ) );}
		}
		return null;
	}
	private function regular( string $path ): bool {
		$root = realpath( WP_PLUGIN_DIR );
		return false !== $root && ! is_link( $path ) && is_file( $path ) && realpath( $path ) === $root . '/' . substr( $path, strlen( WP_PLUGIN_DIR ) + 1 );
	}
	private function item( string $file, array $data ): array {
		$slug      = dirname( $file );
		$version   = is_string( $data['Version'] ?? null ) ? $data['Version'] : '';
		$uri       = is_string( $data['UpdateURI'] ?? null ) ? $data['UpdateURI'] : '';
		$supported = strlen( $file ) <= 190 && strlen( $slug ) <= 64 && 1 === preg_match( '/^[a-z0-9]+(?:-[a-z0-9]+)*$/D', $slug ) && '' === $uri && strlen( $version ) <= 64 && 1 === preg_match( '/^[0-9]+(?:\.[0-9]+)*(?:[-.][a-zA-Z0-9]+)*$/D', $version ) && $this->regular( WP_PLUGIN_DIR . '/' . $file );
		return array(
			'key'         => substr( hash( 'sha256', $file ), 0, 32 ),
			'file'        => $file,
			'label'       => is_string( $data['Name'] ?? null ) ? $data['Name'] : $file,
			'slug'        => $slug,
			'version'     => $version,
			'fingerprint' => hash( 'sha256', $file . "\n" . $version . "\n" . $uri ),
			'supported'   => $supported,
		);
	}
}
