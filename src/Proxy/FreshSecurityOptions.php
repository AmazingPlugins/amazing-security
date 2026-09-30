<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Proxy;

use AmazingPlugins\Security\Integrity\OptionGateway;
final class FreshSecurityOptions implements OptionGateway {
	public function __construct( private readonly object $db, private readonly OptionGateway $writes ) {}
	public function get( string $key ): mixed {
		if ( ! in_array( $key, array( 'amsec_network_policy', 'amsec_proxy_policy', 'amsec_passkey_policy' ), true ) ) {
			return $this->writes->get( $key ); }
		$previous = $this->db->suppress_errors( true );
		try {
		 // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Shared approval consistency must bypass stale values and cached absence.
			$raw = $this->db->get_var( $this->db->prepare( "SELECT option_value FROM {$this->db->options} WHERE option_name=%s LIMIT 1", $key ) );
			if ( '' !== $this->db->last_error ) {
				throw new \RuntimeException( 'Security policy storage unavailable.' ); }
			return $raw;
		} finally {
			$this->db->suppress_errors( $previous ); }
	}
	public function add( string $key, string $value ): bool {
		return $this->writes->add( $key, $value ); }
	public function set( string $key, string $value ): bool {
		return $this->writes->set( $key, $value ); }
	public function delete( string $key ): void {
		$this->writes->delete( $key ); }
	public function replaceIfSame( string $key, string $expected, string $replacement ): bool {
		return $this->writes->replaceIfSame( $key, $expected, $replacement ); }
	public function deleteIfSame( string $key, string $expected ): bool {
		return $this->writes->deleteIfSame( $key, $expected ); }
}
