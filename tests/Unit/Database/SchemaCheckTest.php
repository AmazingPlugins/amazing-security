<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Database;

use AmazingPlugins\Security\Database\SchemaCheck;
use PHPUnit\Framework\TestCase;

final class SchemaCheckTest extends TestCase {
	private function db( array $existing ): object {
		return new class( $existing ) {
			public function __construct( private array $existing ) {}
			public function esc_like( string $t ): string { return $t; }
			public function prepare( string $q, string $t ): string { return $t; }
			public function get_var( string $t ): ?string { return in_array( $t, $this->existing, true ) ? $t : null; }
		};
	}

	public function testAllTablesPresent(): void {
		$this->assertTrue( SchemaCheck::tablesExist( $this->db( array( 'wp_a', 'wp_b' ) ), 'wp_a', 'wp_b' ) );
	}

	public function testOneMissingTableFails(): void {
		$this->assertFalse( SchemaCheck::tablesExist( $this->db( array( 'wp_a' ) ), 'wp_a', 'wp_b' ) );
	}

	public function testNoTablesFails(): void {
		$this->assertFalse( SchemaCheck::tablesExist( $this->db( array() ), 'wp_a' ) );
	}
}
