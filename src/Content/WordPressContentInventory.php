<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Content;

defined( 'ABSPATH' ) || exit;

use RuntimeException;
final class WordPressContentInventory implements ContentInventory {
	public function __construct( private readonly object $db ) {}
	public function bounds(): array {
		return $this->quiet(
			function (): array {
				// Global primary-key watermarks avoid reading content or establishing a frozen database snapshot.
           // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Bounded scalar watermarks on core primary keys.
				$post = $this->db->get_var( "SELECT MAX(ID) FROM {$this->db->posts}" );
				$this->checkError();
           // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Bounded scalar watermark on core primary key.
				$comment = $this->db->get_var( "SELECT MAX(comment_ID) FROM {$this->db->comments}" );
				$this->checkError();
				return array(
					'post'    => max( 0, (int) $post ),
					'comment' => max( 0, (int) $comment ),
				);
			}
		);
	}
	public function candidates( string $kind, int $after, int $max, int $limit ): array {
		return $this->quiet(
			function () use ( $kind, $after, $max, $limit ): array {
				list( $from, $id, $body, $where ) = $this->queryParts( $kind );
				$limit                            = max( 1, min( 50, $limit ) );
				// SHA2 is computed only for bounded source fields; contents never enter the metadata result.
           // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- At most 50 eligible metadata rows with no contents or personal fields.
				$rows = $this->db->get_results( $this->db->prepare( "SELECT {$id} AS id,OCTET_LENGTH({$body}) AS bytes,CASE WHEN OCTET_LENGTH({$body})<=131072 THEN SHA2({$body},256) ELSE '' END AS hash FROM {$from} WHERE {$where} AND {$id}>%d AND {$id}<=%d ORDER BY {$id} ASC LIMIT %d", $after, $max, $limit ), 'ARRAY_A' );
				$this->checkError();
				if ( ! is_array( $rows ) ) {
					throw new RuntimeException( 'Content metadata unavailable.' );
				}
				return array_map(
					static fn( array $row ): array => array(
						'id'    => (int) $row['id'],
						'bytes' => (int) $row['bytes'],
						'hash'  => is_string( $row['hash'] ) ? $row['hash'] : '',
					),
					$rows
				);
			}
		);
	}
	public function read( string $kind, int $itemId, string $hash ): ?string {
		if ( ! preg_match( '/^[a-f0-9]{64}$/D', $hash ) || $itemId < 1 ) {
			return null;
		}
		return $this->quiet(
			function () use ( $kind, $itemId, $hash ): ?string {
				list( $from, $id, $body, $where ) = $this->queryParts( $kind );
           // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Read one still-eligible bounded item matching its captured content hash.
				$row = $this->db->get_row( $this->db->prepare( "SELECT {$body} AS body FROM {$from} WHERE {$where} AND {$id}=%d AND OCTET_LENGTH({$body})<=131072 AND BINARY SHA2({$body},256)=BINARY %s LIMIT 1", $itemId, $hash ), 'ARRAY_A' );
				$this->checkError();
				return is_array( $row ) && is_string( $row['body'] ?? null ) ? $row['body'] : null;
			}
		);
	}
	private function queryParts( string $kind ): array {
		$eligible = "p.post_type IN ('post','page') AND p.post_status='publish' AND p.post_password=''";
		return match ( $kind ) {
			'post' => array( "{$this->db->posts} p", 'p.ID', 'p.post_content', $eligible ),
			'comment' => array( "{$this->db->comments} c INNER JOIN {$this->db->posts} p ON p.ID=c.comment_post_ID", 'c.comment_ID', 'c.comment_content', $eligible . " AND c.comment_approved='1' AND c.comment_type IN ('','comment')" ),
			default => throw new \InvalidArgumentException( 'Unsupported content scope.' ),
		};
	}
	private function quiet( callable $callback ): mixed {
		$prior = $this->db->suppress_errors( true );
		try {
			return $callback();
		} finally {
			$this->db->suppress_errors( $prior );
		}
	}
	private function checkError(): void {
		if ( '' !== $this->db->last_error ) {
			throw new RuntimeException( 'Content storage unavailable.' );
		} }
}
