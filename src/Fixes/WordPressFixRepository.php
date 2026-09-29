<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Fixes;

use Closure;
use RuntimeException;
use Throwable;

final class WordPressFixRepository implements FixRepository {
	private readonly string $proposals;
	private readonly string $auditTable;
	private readonly ?Closure $beforeAudit;

	public function __construct( private readonly object $db, ?callable $beforeAudit = null ) {
		$this->proposals   = $db->prefix . 'amsec_fix_proposals';
		$this->auditTable  = $db->prefix . 'amsec_fix_audit';
		$this->beforeAudit = null === $beforeAudit ? null : Closure::fromCallable( $beforeAudit );
	}

	public function create( FixProposal $proposal ): bool {
		if ( ! $this->transactionalTables() ) {
			return false;
		}
		$lockName = 'amsec_fix_' . substr( hash( 'sha256', $this->proposals ), 0, 32 );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Serialize proposal quota admission.
		$locked = $this->db->get_var( $this->db->prepare( 'SELECT GET_LOCK(%s, 0)', $lockName ) );
		if ( 1 !== (int) $locked || '' !== $this->db->last_error ) {
			return false;
		}
		try {
			if ( $this->recentForUser( $proposal->requesterId, $proposal->createdAt - 3600 ) >= 5 || $this->pendingCount( $proposal->createdAt ) >= 20 ) {
				return false;
			}
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- This insert is bounded to the plugin-owned proposal table.
			return 1 === $this->db->insert(
				$this->proposals,
				array(
					'id'           => $proposal->id,
					'finding_id'   => $proposal->findingId,
					'recipe_id'    => $proposal->recipeId,
					'before_mode'  => $proposal->beforeMode,
					'after_mode'   => $proposal->afterMode,
					'fingerprint'  => $proposal->fingerprint,
					'requester_id' => $proposal->requesterId,
					'status'       => $proposal->status,
					'created_at'   => $proposal->createdAt,
					'expires_at'   => $proposal->expiresAt,
				)
			);
		} finally {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Release the short quota admission lock.
			$this->db->get_var( $this->db->prepare( 'SELECT RELEASE_LOCK(%s)', $lockName ) );
		}
	}

	public function get( string $id ): ?FixProposal {
		if ( ! preg_match( '/^[a-f0-9]{32}$/D', $id ) ) {
			return null;
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Proposal state must be current for approval.
		$row = $this->db->get_row( $this->db->prepare( "SELECT * FROM {$this->proposals} WHERE id = %s", $id ), ARRAY_A );
		return is_array( $row ) ? $this->hydrate( $row ) : null;
	}

	public function apply( string $id, int $approverId, int $now ): string {
		return $this->transition( $id, $approverId, $now, false );
	}

	public function rollback( string $id, int $approverId, int $now ): string {
		return $this->transition( $id, $approverId, $now, true );
	}

	public function audit( string $id ): array {
		if ( ! preg_match( '/^[a-f0-9]{32}$/D', $id ) ) {
			return array();
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Audit events are append-only, read after writes.
		$rows = $this->db->get_results( $this->db->prepare( "SELECT event, actor_id, created_at, reason FROM {$this->auditTable} WHERE proposal_id = %s ORDER BY event_id ASC LIMIT 20", $id ), ARRAY_A );
		return is_array( $rows ) ? $rows : array();
	}

	public function recentForUser( int $userId, int $since ): int {
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Quota must use current proposal rows.
		$count = $this->db->get_var( $this->db->prepare( "SELECT COUNT(*) FROM {$this->proposals} WHERE requester_id = %d AND created_at >= %d", $userId, $since ) );
		return null === $count || '' !== $this->db->last_error ? PHP_INT_MAX : (int) $count;
	}

	public function pendingCount( int $now ): int {
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Quota must use current pending rows.
		$count = $this->db->get_var( $this->db->prepare( "SELECT COUNT(*) FROM {$this->proposals} WHERE status = %s AND expires_at > %d", 'pending', $now ) );
		return null === $count || '' !== $this->db->last_error ? PHP_INT_MAX : (int) $count;
	}

	public function cleanup( int $now ): void {
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Keep only short-lived proposals and 90 days of audit history.
		$this->db->query( $this->db->prepare( "DELETE FROM {$this->proposals} WHERE (status IN ('pending', 'expired', 'refused') AND expires_at < %d) OR (status IN ('applied', 'rolled_back') AND created_at < %d)", $now - 86400, $now - 90 * 86400 ) );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Bounded audit retention.
		$this->db->query( $this->db->prepare( "DELETE FROM {$this->auditTable} WHERE created_at < %d", $now - 90 * 86400 ) );
	}

	private function transition( string $id, int $actorId, int $now, bool $rollback ): string {
		if ( ! preg_match( '/^[a-f0-9]{32}$/D', $id ) || $actorId < 1 || ! $this->transactionalTables() ) {
			return 'unavailable';
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Transaction covers proposal state, option CAS, and audit.
		if ( false === $this->db->query( 'START TRANSACTION' ) ) {
			return 'unavailable';
		}
		try {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Row lock enforces one-time transition.
			$row = $this->db->get_row( $this->db->prepare( "SELECT * FROM {$this->proposals} WHERE id = %s FOR UPDATE", $id ), ARRAY_A );
			if ( ! is_array( $row ) || '' !== $this->db->last_error ) {
				return $this->abort( 'unavailable' );
			}
			$proposal = $this->hydrate( $row );
			if ( ! hash_equals( $proposal->fingerprint, (string) $row['fingerprint'] ) ) {
				throw new RuntimeException( 'Proposal fingerprint mismatch.' );
			}
			if ( $rollback ? 'applied' !== $proposal->status : 'pending' !== $proposal->status ) {
				return $this->abort( 'already_used' );
			}
			if ( $rollback ? ! $proposal->canRollback( $now ) : $proposal->isExpired( $now ) ) {
				if ( ! $rollback ) {
					$this->setStatus( $id, 'expired', array() );
					$this->appendAudit( $id, 'expired', $actorId, $now, 'expired' );
					return $this->commit( 'expired' );
				}
				return $this->abort( 'expired' );
			}
			if ( ! $rollback ) {
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Serialize approval with a concurrent MCP opt-out.
				$permission = $this->db->get_row( $this->db->prepare( "SELECT option_value FROM {$this->db->options} WHERE option_name = %s FOR UPDATE", 'amazing_security_mcp_enabled' ), ARRAY_A );
				if ( '' !== $this->db->last_error ) {
					throw new RuntimeException( 'Could not read MCP permission.' );
				}
				if ( ! is_array( $permission ) || '1' !== $permission['option_value'] ) {
					return $this->abort( 'unavailable' );
				}
			}
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Lock the exact option row before compare-and-swap.
			$option = $this->db->get_row( $this->db->prepare( "SELECT option_value FROM {$this->db->options} WHERE option_name = %s FOR UPDATE", 'amsec_login_rate_mode' ), ARRAY_A );
			if ( '' !== $this->db->last_error ) {
				throw new RuntimeException( 'Could not read login mode.' );
			}
			$current  = is_array( $option ) ? (string) $option['option_value'] : 'off';
			$expected = $rollback ? $proposal->afterMode : $proposal->beforeMode;
			$next     = $rollback ? $proposal->beforeMode : $proposal->afterMode;
			if ( $current !== $expected ) {
				$this->appendAudit( $id, 'refused', $actorId, $now, 'setting_changed' );
				if ( ! $rollback ) {
					$this->setStatus( $id, 'refused', array() );
				}
				return $this->commit( 'stale' );
			}
			if ( is_array( $option ) ) {
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Exact option CAS inside the transaction.
				$changed = $this->db->query( $this->db->prepare( "UPDATE {$this->db->options} SET option_value = %s WHERE option_name = %s AND BINARY option_value = BINARY %s", $next, 'amsec_login_rate_mode', $expected ) );
			} else {
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- The default off option was absent; unique option_name protects insertion.
				$changed = $this->db->query( $this->db->prepare( "INSERT INTO {$this->db->options} (option_name, option_value, autoload) VALUES (%s, %s, %s)", 'amsec_login_rate_mode', $next, 'off' ) );
			}
			if ( 1 !== $changed ) {
				throw new RuntimeException( 'Could not change login mode.' );
			}
			if ( $rollback ) {
				$this->setStatus( $id, 'rolled_back', array( 'rolled_back_at' => $now ) );
				$this->appendAudit( $id, 'rolled_back', $actorId, $now, 'approved' );
				return $this->commit( 'rolled_back', true );
			}
			$this->setStatus(
				$id,
				'applied',
				array(
					'approver_id' => $actorId,
					'applied_at'  => $now,
				)
			);
			$this->appendAudit( $id, 'applied', $actorId, $now, 'approved' );
			return $this->commit( 'applied', true );
		} catch ( Throwable ) {
			return $this->abort( 'unavailable', true );
		}
	}

	private function setStatus( string $id, string $status, array $extra ): void {
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Proposal row is locked inside transaction.
		if ( 1 !== $this->db->update( $this->proposals, array_merge( array( 'status' => $status ), $extra ), array( 'id' => $id ) ) ) {
			throw new RuntimeException( 'Could not save proposal state.' );
		}
	}

	private function appendAudit( string $id, string $event, int $actorId, int $now, string $reason ): void {
		if ( null !== $this->beforeAudit ) {
			( $this->beforeAudit )();
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Audit insert shares the proposal transaction.
		if ( 1 !== $this->db->insert(
			$this->auditTable,
			array(
				'proposal_id' => $id,
				'event'       => $event,
				'actor_id'    => $actorId,
				'created_at'  => $now,
				'reason'      => $reason,
			)
		) ) {
			throw new RuntimeException( 'Could not save fix audit.' );
		}
	}

	private function transactionalTables(): bool {
		$names = array( $this->proposals, $this->auditTable, $this->db->options );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Approval must fail closed unless all three tables use transactions.
		$engines = $this->db->get_col( $this->db->prepare( 'SELECT ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME IN (%s, %s, %s)', ...$names ) );
		return is_array( $engines ) && 3 === count( $engines ) && array() === array_filter( $engines, static fn( $engine ): bool => 'InnoDB' !== $engine );
	}

	private function hydrate( array $row ): FixProposal {
		return new FixProposal( (string) $row['id'], (string) $row['finding_id'], (string) $row['recipe_id'], (string) $row['before_mode'], (string) $row['after_mode'], (int) $row['requester_id'], (int) $row['created_at'], (int) $row['expires_at'], (string) $row['status'], null === $row['approver_id'] ? null : (int) $row['approver_id'], null === $row['applied_at'] ? null : (int) $row['applied_at'], null === $row['rolled_back_at'] ? null : (int) $row['rolled_back_at'] );
	}

	private function commit( string $result, bool $optionChanged = false ): string {
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- End of atomic fix transition.
		if ( false === $this->db->query( 'COMMIT' ) ) {
			return $this->abort( 'unavailable', $optionChanged );
		}
		if ( $optionChanged ) {
			$this->clearOptionCache();
		}
		return $result;
	}

	private function abort( string $result, bool $optionChanged = false ): string {
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Roll back every partially attempted transition.
		$this->db->query( 'ROLLBACK' );
		if ( $optionChanged ) {
			$this->clearOptionCache();
		}
		return $result;
	}

	private function clearOptionCache(): void {
		wp_cache_delete( 'amsec_login_rate_mode', 'options' );
		wp_cache_delete( 'alloptions', 'options' );
		wp_cache_delete( 'notoptions', 'options' );
	}
}
