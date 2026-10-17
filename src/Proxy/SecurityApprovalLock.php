<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Proxy;

defined( 'ABSPATH' ) || exit;

final class SecurityApprovalLock {
	public function __construct( private readonly object $db ) {}
	public function run( callable $operation ): string {
		$lock = 'amsec_net_policy_' . substr( hash( 'sha256', $this->db->prefix . ( defined( 'DB_NAME' ) ? DB_NAME : '' ) ), 0, 32 );
		$old  = $this->db->suppress_errors( true );
		try {
		 // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Zero-wait lock serializes the two related approved policy edits.
			if ( '1' !== (string) $this->db->get_var( $this->db->prepare( 'SELECT GET_LOCK(%s,0)', $lock ) ) || '' !== $this->db->last_error ) {
				return 'busy'; }
			try {
				return $operation(); } finally {
					// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Release before redirect/termination and on every operation exception.
					$this->db->get_var( $this->db->prepare( 'SELECT RELEASE_LOCK(%s)', $lock ) );
				}
		} catch ( \Throwable ) {
			return 'failed';
		} finally {
			$this->db->suppress_errors( $old ); }
	}
}
