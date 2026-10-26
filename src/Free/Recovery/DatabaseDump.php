<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Free\Recovery;

defined( 'ABSPATH' ) || exit;

use Closure;

/** Builds a prefixed SQL dump in memory. Over the cap, the body is discarded. */
final class DatabaseDump {
	public const MAX_TABLES = 50;
	public const MAX_BYTES  = 20971520;

	private readonly Closure $escape;
	private readonly int $maxTables;
	private readonly int $maxBytes;

	public function __construct(
		private readonly TableSource $source,
		callable $escape,
		int $maxTables = self::MAX_TABLES,
		int $maxBytes = self::MAX_BYTES,
	) {
		$this->escape    = Closure::fromCallable( $escape );
		$this->maxTables = max( 1, min( self::MAX_TABLES, $maxTables ) );
		$this->maxBytes  = max( 1, min( self::MAX_BYTES, $maxBytes ) );
	}

	public function build( string $prefix, Approval $approval, bool $confirmed ): ChangeResult {
		$denial = $approval->denial();
		if ( null !== $denial ) {
			return ChangeResult::failure( $denial );
		}
		if ( ! $confirmed ) {
			return ChangeResult::failure( __( 'Confirm the database download before it starts.', 'amazingplugins-security-scanner' ) );
		}
		if ( 1 !== preg_match( '/\A[A-Za-z0-9_]+\z/', $prefix ) ) {
			return ChangeResult::failure( __( 'The table prefix is empty or unexpected. No SQL file was created.', 'amazingplugins-security-scanner' ) );
		}
		$names = array();
		foreach ( $this->source->tableNames( $prefix ) as $name ) {
			if ( is_string( $name ) && str_starts_with( $name, $prefix ) && 1 === preg_match( '/\A[A-Za-z0-9_]+\z/', $name ) ) {
				$names[] = $name;
			}
		}
		$names = array_values( array_unique( $names ) );
		if ( count( $names ) > $this->maxTables ) {
			return ChangeResult::failure(
				sprintf(
					/* translators: %d: maximum number of tables in one dump. */
					__( 'There are more than %d prefixed tables. No SQL file was created.', 'amazingplugins-security-scanner' ),
					$this->maxTables
				)
			);
		}
		$sql = "-- AmazingPlugins Security Scanner prefixed table dump\n-- This copy does not mean the site is clean.\n\n";
		foreach ( $names as $table ) {
			$create = $this->source->createTable( $table );
			if ( ! is_string( $create ) || ! $this->safeCreate( $create ) ) {
				return ChangeResult::failure( __( 'A table definition was missing or included another database. No SQL file was created.', 'amazingplugins-security-scanner' ) );
			}
			$quoted = '`' . $table . '`';
			$block  = 'DROP TABLE IF EXISTS ' . $quoted . ";\n" . rtrim( $create, " \t\r\n;" ) . ";\n";
			$next   = $this->append( $sql, $block );
			if ( null === $next ) {
				return $this->tooLarge();
			}
			$sql    = $next;
			$offset = 0;
			while ( $offset < 1000000 ) {
				$rows = $this->source->rows( $table, 100, $offset );
				if ( array() === $rows ) {
					break;
				}
				foreach ( $rows as $row ) {
					$line = $this->insert( $table, $row );
					if ( null === $line ) {
						return ChangeResult::failure( __( 'A table row could not be escaped. No SQL file was created.', 'amazingplugins-security-scanner' ) );
					}
					$next = $this->append( $sql, $line );
					if ( null === $next ) {
						return $this->tooLarge();
					}
					$sql = $next;
				}
				$count = count( $rows );
				if ( $count < 100 ) {
					break;
				}
				$offset += $count;
			}
			if ( $offset >= 1000000 ) {
				return ChangeResult::failure( __( 'A table is too large to export here. No SQL file was created.', 'amazingplugins-security-scanner' ) );
			}
		}
		if ( preg_match( '/CREATE\s+DATABASE/i', $sql ) ) {
			return ChangeResult::failure( __( 'The SQL dump included a database statement. No file was created.', 'amazingplugins-security-scanner' ) );
		}
		return ChangeResult::success( __( 'Prefixed tables are ready to download.', 'amazingplugins-security-scanner' ), $sql );
	}

	private function tooLarge(): ChangeResult {
		return ChangeResult::failure( __( 'The SQL dump would pass the size cap. No file was created.', 'amazingplugins-security-scanner' ) );
	}

	private function safeCreate( string $create ): bool {
		if ( str_contains( $create, "\0" ) || preg_match( '/CREATE\s+DATABASE/i', $create ) ) {
			return false;
		}
		return 1 === preg_match( '/CREATE\s+TABLE/i', $create );
	}

	private function append( string $sql, string $chunk ): ?string {
		if ( strlen( $sql ) + strlen( $chunk ) > $this->maxBytes ) {
			return null;
		}
		return $sql . $chunk;
	}

	private function insert( string $table, mixed $row ): ?string {
		if ( ! is_array( $row ) ) {
			return null;
		}
		$columns = array();
		$values  = array();
		foreach ( $row as $column => $value ) {
			$name    = $this->identifier( (string) $column );
			$literal = $this->literal( $value );
			if ( null === $name || null === $literal ) {
				return null;
			}
			$columns[] = $name;
			$values[]  = $literal;
		}
		$tableName = $this->identifier( $table );
		if ( null === $tableName || array() === $columns ) {
			return null;
		}
		return 'INSERT INTO ' . $tableName . ' (' . implode( ', ', $columns ) . ') VALUES (' . implode( ', ', $values ) . ");\n";
	}

	private function identifier( string $name ): ?string {
		if ( 1 !== preg_match( '/\A[A-Za-z0-9_]+\z/', $name ) ) {
			return null;
		}
		return '`' . $name . '`';
	}

	private function literal( mixed $value ): ?string {
		if ( null === $value ) {
			return 'NULL';
		}
		if ( is_bool( $value ) ) {
			$value = $value ? '1' : '0';
		} elseif ( is_int( $value ) ) {
			$value = (string) $value;
		} elseif ( is_float( $value ) ) {
			if ( ! is_finite( $value ) ) {
				return null;
			}
			$value = (string) $value;
		} elseif ( ! is_string( $value ) ) {
			return null;
		}
		$escaped = ( $this->escape )( $value );
		if ( ! is_string( $escaped ) ) {
			return null;
		}
		return "'" . $escaped . "'";
	}
}
