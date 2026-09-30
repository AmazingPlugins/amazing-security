<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Activity;

use RuntimeException;

final class ActivityRepository {
	private readonly string $table;

	public function __construct( private readonly object $db ) {
		$this->table = $db->prefix . 'amsec_activity';
	}

	public function append( ActivityEvent $event ): bool {
		return $this->quiet( fn(): bool => $this->appendQuiet( $event ) );
	}

	private function appendQuiet( ActivityEvent $event ): bool {
		$lock = 'amsec_activity_' . substr( hash( 'sha256', $this->table . ( defined( 'DB_NAME' ) ? DB_NAME : '' ) ), 0, 32 );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Zero-wait lock bounds concurrent quota admission.
		if ( '1' !== (string) $this->db->get_var( $this->db->prepare( 'SELECT GET_LOCK(%s, 0)', $lock ) ) ) {
			return false;
		}
		try {
			if ( 'login_failed' === $event->event ) {
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Current failed-login quota cannot be cached.
				$count = $this->db->get_var( $this->db->prepare( "SELECT COUNT(*) FROM {$this->table} WHERE event = %s AND created_at >= %d", 'login_failed', $event->createdAt - 60 ) );
				$this->checkError();
				if ( (int) $count >= 100 ) {
					return false;
				}
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Reserve history capacity for administrative events.
				$count = $this->db->get_var( $this->db->prepare( "SELECT COUNT(*) FROM {$this->table} WHERE event = %s", 'login_failed' ) );
				$this->checkError();
				if ( (int) $count >= 2000 ) {
					// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Bounded eviction affects failed-login rows only.
					$this->db->query( $this->db->prepare( "DELETE FROM {$this->table} WHERE event = %s ORDER BY id ASC LIMIT 100", 'login_failed' ) );
					$this->checkError();
				}
			}
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Enforce a hard plugin-owned row budget.
			$count = $this->db->get_var( "SELECT COUNT(*) FROM {$this->table}" );
			$this->checkError();
			if ( (int) $count >= 10000 ) {
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Bounded oldest-event eviction.
				$this->db->query( "DELETE FROM {$this->table} ORDER BY id ASC LIMIT 100" );
				$this->checkError();
			}
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Fixed validated fields in plugin-owned event storage.
			$written = $this->db->insert( $this->table, $event->row(), array( '%s', '%d', '%d', '%s', '%d' ) );
			$this->checkError();
			return 1 === $written;
		} finally {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Release the admission lock on every exit path.
			$this->db->get_var( $this->db->prepare( 'SELECT RELEASE_LOCK(%s)', $lock ) );
		}
	}

	public function page( int $page = 1, string $event = '' ): array {
		return $this->quiet( fn(): array => $this->pageQuiet( $page, $event ) );
	}

	private function pageQuiet( int $page, string $event ): array {
		$page = max( 1, min( 200, $page ) );
		if ( '' !== $event && ! in_array( $event, ActivityEvent::TYPES, true ) ) {
			throw new \InvalidArgumentException( 'Unsupported event filter.' );
		}
		$where = $this->db->prepare( ' WHERE created_at >= %d', time() - 30 * DAY_IN_SECONDS );
		if ( '' !== $event ) {
			$where .= $this->db->prepare( ' AND event = %s', $event );
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Administrator timeline is fresh and limited to 50 rows.
		$rows = $this->db->get_results( $this->db->prepare( "SELECT id, event, actor_id, user_id, target, created_at FROM {$this->table}{$where} ORDER BY id DESC LIMIT 50 OFFSET %d", ( $page - 1 ) * 50 ), ARRAY_A );
		$this->checkError();
		return is_array( $rows ) ? $rows : array();
	}

	public function cleanup( int $now ): void {
		$this->quiet( fn() => $this->cleanupQuiet( $now ) );
	}

	private function cleanupQuiet( int $now ): void {
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Delete at most 1000 expired event records per cleanup.
		$this->db->query( $this->db->prepare( "DELETE FROM {$this->table} WHERE created_at < %d ORDER BY id ASC LIMIT 1000", $now - 30 * DAY_IN_SECONDS ) );
		$this->checkError();
	}

	private function quiet( callable $operation ): mixed {
		$previous = $this->db->suppress_errors( true );
		try {
			return $operation();
		} finally {
			$this->db->suppress_errors( $previous );
		}
	}

	private function checkError(): void {
		if ( '' !== $this->db->last_error ) {
			throw new RuntimeException( 'Activity storage unavailable.' );
		}
	}
}
