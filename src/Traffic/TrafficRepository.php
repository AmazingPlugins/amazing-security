<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Traffic;

use RuntimeException;
final class TrafficRepository {
	private readonly string $table;
	public function __construct( private readonly object $db ) {
		$this->table = $db->prefix . 'amsec_traffic'; }
	public function append( TrafficEvent $event, string $revision ): bool {
		try {
			return $this->quiet( fn(): bool=>$this->appendQuiet( $event, $revision ) );
		} catch ( \Throwable ) {
			return false; }
	}
	private function appendQuiet( TrafficEvent $event, string $revision ): bool {
		$lock = 'amsec_traffic_' . substr( hash( 'sha256', $this->table . ( defined( 'DB_NAME' ) ? DB_NAME : '' ) ), 0, 32 );
	 // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Zero-wait lock bounds concurrent quota admission.
		if ( '1' !== (string) $this->db->get_var( $this->db->prepare( 'SELECT GET_LOCK(%s, 0)', $lock ) ) ) {
			return false; }
		try {
			$raw    = $this->freshRaw();
			$policy = ( new TrafficPolicy() )->read( $raw );
			if ( null === $policy || ! $policy['enabled'] || $policy['revision'] !== $revision ) {
				return false; }
		 // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Fixed table-wide hard admission budget.
			$count = $this->db->get_var( "SELECT COUNT(*) FROM {$this->table}" );
			$this->checkError();
			if ( null === $count || ! is_numeric( $count ) || (int) $count >= 5000 ) {
				return false; }
		 // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Indexed recent-row admission budget; no cached quota decisions.
			$recent = $this->db->get_var( $this->db->prepare( "SELECT COUNT(*) FROM {$this->table} WHERE created_at >= %d", $event->row()['created_at'] - 60 ) );
			$this->checkError();
			if ( null === $recent || ! is_numeric( $recent ) || (int) $recent >= 100 ) {
				return false; }
			$row = $event->row();
		 // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Exact fresh-policy guard in the same insert prevents stale revision admission after another request disables collection.
			$written = $this->db->query( $this->db->prepare( "INSERT INTO {$this->table} (created_at,method,category,status,decision) SELECT %d,%s,%s,%d,%s FROM {$this->db->options} WHERE option_name=%s AND BINARY option_value=BINARY %s", $row['created_at'], $row['method'], $row['category'], $row['status'], $row['decision'], 'amsec_traffic_policy', $raw ) );
			$this->checkError();
			return 1 === $written;
		} finally {
		 // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Always release the admission lock.
			$this->db->get_var( $this->db->prepare( 'SELECT RELEASE_LOCK(%s)', $lock ) );
		}
	}
	public function currentPolicy(): ?array {
		try {
			return $this->quiet( fn(): ?array=>( new TrafficPolicy() )->read( $this->freshRaw() ) );
		} catch ( \Throwable ) {
			return null; }
	}
	private function freshRaw(): mixed {
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Policy revocation must bypass this request's options cache.
		$raw = $this->db->get_var( $this->db->prepare( "SELECT option_value FROM {$this->db->options} WHERE option_name=%s LIMIT 1", 'amsec_traffic_policy' ) );
		$this->checkError();
		return $raw;
	}
	public function page( int $page = 1, string $category = '' ): array {
		if ( '' !== $category && ! in_array( $category, TrafficEvent::CATEGORIES, true ) ) {
			throw new \InvalidArgumentException( 'Unsupported traffic filter.' ); }
		return $this->quiet(
			function () use ( $page, $category ): array {
				$where = $this->db->prepare( ' WHERE created_at >= %d AND created_at <= %d', time() - 604800, time() );
				if ( '' !== $category ) {
					$where .= $this->db->prepare( ' AND category = %s', $category ); }
           // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Fresh administrator view, at most 50 rows from the bounded table.
				$rows = $this->db->get_results( $this->db->prepare( "SELECT id,created_at,method,category,status,decision FROM {$this->table}{$where} ORDER BY id DESC LIMIT 50 OFFSET %d", ( max( 1, min( 100, $page ) ) - 1 ) * 50 ), 'ARRAY_A' );
				$this->checkError();
				if ( ! is_array( $rows ) ) {
					throw new RuntimeException( 'Traffic storage unavailable.' ); }
				return $rows;
			}
		);
	}
	public function cleanup( int $now ): void {
		$this->quiet(
			function () use ( $now ): void {
           // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Delete at most 500 expired feature-owned rows per cleanup.
				$this->db->query( $this->db->prepare( "DELETE FROM {$this->table} WHERE created_at < %d ORDER BY id ASC LIMIT 500", $now - 604800 ) );
				$this->checkError();
			}
		);
	}
	private function quiet( callable $operation ): mixed {
		$old = $this->db->suppress_errors( true );
		try {
			return $operation();
		} finally {
			$this->db->suppress_errors( $old ); } }
	private function checkError(): void {
		if ( '' !== $this->db->last_error ) {
			throw new RuntimeException( 'Traffic storage unavailable.' ); } }
}
