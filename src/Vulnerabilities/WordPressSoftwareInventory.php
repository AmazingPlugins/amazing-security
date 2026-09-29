<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Vulnerabilities;

final class WordPressSoftwareInventory implements SoftwareInventory {
	private bool $complete = true;

	/** @param null|callable():array $metadata */
	public function __construct( private readonly mixed $metadata = null ) {}

	public function collect(): array {
		$this->complete = true;
		$data           = null !== $this->metadata ? ( $this->metadata )() : $this->wordpressMetadata();
		$items          = array();
		$core           = $data['core'] ?? array();
		$version        = (string) ( $core['version'] ?? '' );
		// phpcs:ignore WordPress.WP.CapitalPDangit.MisspelledInText, Generic.Formatting.MultipleStatementAlignment.IncorrectWarning -- Canonical feed slug is lowercase.
		$items[] = new InstalledSoftware( 'core', 'wordpress', $version, $this->validVersion( $version ) );
		foreach ( array(
			'plugins' => 'plugin',
			'themes'  => 'theme',
		) as $collection => $type ) {
			foreach ( $data[ $collection ] ?? array() as $record ) {
				if ( count( $items ) >= 1000 ) {
					$this->complete = false;
					break 2;
				}
				if ( ! is_array( $record ) ) {
					continue;
				}
				$rawSlug  = 'plugin' === $type ? dirname( (string) ( $record['file'] ?? '' ) ) : (string) ( $record['slug'] ?? '' );
				$slug     = $this->validSlug( $rawSlug ) ? $rawSlug : 'unsupported-' . count( $items );
				$version  = (string) ( $record['version'] ?? '' );
				$trusted  = (string) ( $record['repository_slug'] ?? '' );
				$eligible = $slug === $trusted && true === ( $record['verified_release'] ?? false ) && $this->validSlug( $slug ) && $this->validVersion( $version ) && '' === (string) ( $record['update_uri'] ?? '' );
				$items[]  = new InstalledSoftware( $type, $slug, $version, $eligible );
			}
		}
		return $items;
	}

	public function complete(): bool {
		return $this->complete;
	}

	private function validSlug( string $value ): bool {
		return 1 === preg_match( '/^[a-z0-9]+(?:-[a-z0-9]+)*$/D', $value );
	}

	private function validVersion( string $value ): bool {
		return 1 === preg_match( '/^[0-9]+(?:\.[0-9]+)*(?:[-.][a-zA-Z0-9]+)*$/D', $value ) && strlen( $value ) <= 64;
	}

	private function wordpressMetadata(): array {
		global $wp_version;
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$pluginUpdates = get_site_transient( 'update_plugins' );
		$themeUpdates  = get_site_transient( 'update_themes' );
		$plugins       = array();
		foreach ( get_plugins() as $file => $details ) {
			$update    = $pluginUpdates->response[ $file ] ?? $pluginUpdates->no_update[ $file ] ?? null;
			$package   = is_object( $update ) ? (string) ( $update->package ?? '' ) : '';
			$slug      = is_object( $update ) && $this->officialPackage( $package ) ? (string) ( $update->slug ?? '' ) : '';
			$plugins[] = array(
				'file'            => $file,
				'version'         => (string) ( $details['Version'] ?? '' ),
				'update_uri'      => (string) ( $details['UpdateURI'] ?? '' ),
				'repository_slug' => $slug,
			);
		}
		$themes = array();
		foreach ( wp_get_themes() as $slug => $theme ) {
			$update   = $themeUpdates->response[ $slug ] ?? $themeUpdates->no_update[ $slug ] ?? null;
			$package  = is_array( $update ) ? (string) ( $update['package'] ?? '' ) : '';
			$trusted  = is_array( $update ) && $this->officialPackage( $package ) ? $slug : '';
			$themes[] = array(
				'slug'            => $slug,
				'version'         => $theme->get( 'Version' ),
				'repository_slug' => $trusted,
			);
		}
		return array(
			'core'    => array( 'version' => (string) $wp_version ),
			'plugins' => $plugins,
			'themes'  => $themes,
		);
	}

	private function officialPackage( string $url ): bool {
		// phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url -- Pure metadata validation.
		return 'https' === parse_url( $url, PHP_URL_SCHEME ) && 'downloads.wordpress.org' === parse_url( $url, PHP_URL_HOST );
	}
}
