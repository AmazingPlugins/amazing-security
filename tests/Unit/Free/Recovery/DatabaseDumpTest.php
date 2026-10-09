<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Free\Recovery;

use AmazingPlugins\Security\Free\Recovery\Approval;
use AmazingPlugins\Security\Free\Recovery\DatabaseDump;
use AmazingPlugins\Security\Free\Recovery\TableSource;
use PHPUnit\Framework\TestCase;

final class DatabaseDumpTest extends TestCase {
	public function test_refuses_when_over_the_table_cap(): void {
		$source = new class() implements TableSource {
			public function tableNames( string $prefix ): array {
				$names = array();
				for ( $index = 0; $index < 51; $index++ ) {
					$names[] = $prefix . 't' . $index;
				}
				return $names;
			}

			public function createTable( string $table ): ?string {
				throw new \RuntimeException( 'partial read' );
			}

			public function rows( string $table, int $limit, int $offset ): array {
				throw new \RuntimeException( 'partial read' );
			}
		};

		$result = ( new DatabaseDump( $source, static fn( string $value ): string => addslashes( $value ) ) )->build( 'wp_', new Approval( true, true, true ), true );

		self::assertFalse( $result->ok );
		self::assertSame( '', $result->body );
		self::assertStringContainsString( '50', $result->message );
	}

	public function test_refuses_partial_output_over_the_byte_cap(): void {
		$source = new class() implements TableSource {
			public function tableNames( string $prefix ): array {
				return array( $prefix . 'options' );
			}

			public function createTable( string $table ): ?string {
				return 'CREATE TABLE `' . $table . '` (id INT)';
			}

			public function rows( string $table, int $limit, int $offset ): array {
				return 0 === $offset ? array( array( 'id' => str_repeat( 'a', 80 ) ) ) : array();
			}
		};

		$result = ( new DatabaseDump( $source, static fn( string $value ): string => addslashes( $value ), 50, 80 ) )->build( 'wp_', new Approval( true, true, true ), true );

		self::assertFalse( $result->ok );
		self::assertSame( '', $result->body );
	}

	public function test_dump_escapes_values_and_omits_other_databases(): void {
		$source = new class() implements TableSource {
			public function tableNames( string $prefix ): array {
				return array( $prefix . 'options', 'mysql_user' );
			}

			public function createTable( string $table ): ?string {
				return 'CREATE TABLE `' . $table . '` (option_value text)';
			}

			public function rows( string $table, int $limit, int $offset ): array {
				return 0 === $offset ? array( array( 'option_value' => "O'Brien 100%" ) ) : array();
			}
		};

		$result = ( new DatabaseDump( $source, static fn( string $value ): string => addslashes( $value ) ) )->build( 'wp_', new Approval( true, true, true ), true );

		self::assertTrue( $result->ok );
		self::assertStringContainsString( 'CREATE TABLE `wp_options`', $result->body );
		self::assertStringContainsString( "O\\'Brien 100%", $result->body );
		self::assertStringNotContainsString( 'CREATE DATABASE', $result->body );
		self::assertStringNotContainsString( 'mysql_user', $result->body );
		self::assertStringContainsString( 'does not mean the site is clean', $result->body );
	}

	public function test_create_database_statement_discards_the_dump(): void {
		$source = new class() implements TableSource {
			public function tableNames( string $prefix ): array {
				return array( $prefix . 'options' );
			}

			public function createTable( string $table ): ?string {
				return 'CREATE DATABASE other';
			}

			public function rows( string $table, int $limit, int $offset ): array {
				return array();
			}
		};

		$result = ( new DatabaseDump( $source, static fn( string $value ): string => addslashes( $value ) ) )->build( 'wp_', new Approval( true, true, true ), true );

		self::assertFalse( $result->ok );
		self::assertSame( '', $result->body );
	}
}
