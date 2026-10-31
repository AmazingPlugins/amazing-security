<?php
namespace AmazingPlugins\Security\Tests\Unit\Bots;

use AmazingPlugins\Security\Bots\BotCounterStore;
use PHPUnit\Framework\TestCase;
final class BotStorageTest extends TestCase {
	public function test_readable_but_unwritable_storage_is_unavailable(): void {
		$db = new class() {
			public string $prefix     = 'wp_';
			public string $last_error = '';
			public function suppress_errors( $value ) {
				return false; }
			public function get_var( $sql ) {
				return 0; }
			public function query( $sql ) {
				$this->last_error = 'write denied';
				return false; }
		};
		self::assertFalse( ( new BotCounterStore( $db ) )->available() );
	}
	public function test_failed_table_creation_is_not_a_ready_schema(): void {
		$db = new class() {
			public string $prefix     = 'wp_';
			public string $last_error = '';
			public function suppress_errors( $value ) {
				return false; }
			public function query( $sql ) {
				$this->last_error = 'missing table';
				return false; }
		};
		self::assertFalse( BotCounterStore::schemaReady( $db ) );
	}
	public function test_block_store_flags_once_and_rejects_bad_keys(): void {
		$db    = new class() {
			public string $prefix     = 'wp_';
			public string $last_error = '';
			public array $sql         = array();
			public int $rows          = 1;
			public $var               = null;
			public function suppress_errors( $value ) {
				return false; }
			public function prepare( $sql, ...$args ) {
				return vsprintf( str_replace( array( '%s', '%d' ), array( "'%s'", '%d' ), $sql ), $args ); }
			public function query( $sql ) {
				$this->sql[] = $sql;
				return $this->rows; }
			public function get_var( $sql ) {
				$this->sql[] = $sql;
				return $this->var; }
		};
		$store = new BotCounterStore( $db );
		$key   = str_repeat( 'a', 64 );
		self::assertFalse( $store->block( 'not-a-key', 200, 100 ) );
		self::assertFalse( $store->flag( 'not-a-key', 100, 600 ) );
		self::assertSame( array(), $db->sql );
		self::assertTrue( $store->flag( $key, 1000, 600 ) );
		self::assertStringContainsString( 'flagged_at<=400', end( $db->sql ) );
		$db->rows = 0;
		self::assertFalse( $store->flag( $key, 1001, 600 ), 'Already flagged inside the window.' );
		$db->rows = 1;
		self::assertTrue( $store->block( $key, 4600, 1000 ) );
		self::assertStringContainsString( 'GREATEST(blocked_until', end( $db->sql ) );
		self::assertFalse( $store->blocked( $key, 1000 ) );
		$db->var = '1';
		self::assertTrue( $store->blocked( $key, 1000 ) );
		self::assertStringContainsString( 'blocked_until>1000', end( $db->sql ) );
	}
}
