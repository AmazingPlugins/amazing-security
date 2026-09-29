<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Login;

use AmazingPlugins\Security\Login\WordPressTotpStore;
use PHPUnit\Framework\TestCase;

final class WordPressTotpStoreTest extends TestCase {
	public function test_database_error_is_distinct_from_an_unenrolled_account(): void {
		$db = new class {
			public string $usermeta = 'wp_usermeta';
			public string $last_error = 'database unavailable';
			public function prepare( string $query, mixed ...$values ): string { return $query; }
			public function get_results( string $query, string $format ): ?array { return null; }
		};
		$this->expectException( \RuntimeException::class );
		( new WordPressTotpStore( $db ) )->isEnrolled( 7 );
	}
}
