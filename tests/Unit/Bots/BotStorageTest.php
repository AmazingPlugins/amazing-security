<?php
namespace AmazingPlugins\Security\Tests\Unit\Bots;
use AmazingPlugins\Security\Bots\BotCounterStore;
use PHPUnit\Framework\TestCase;
final class BotStorageTest extends TestCase {
 public function test_readable_but_unwritable_storage_is_unavailable(): void {
  $db = new class {
   public string $prefix = 'wp_'; public string $last_error = '';
   public function suppress_errors($value) { return false; }
   public function get_var($sql) { return 0; }
   public function query($sql) { $this->last_error = 'write denied'; return false; }
  };
  self::assertFalse((new BotCounterStore($db))->available());
 }
 public function test_failed_table_creation_is_not_a_ready_schema(): void {
  $db = new class {
   public string $prefix = 'wp_'; public string $last_error = '';
   public function suppress_errors($value) { return false; }
   public function query($sql) { $this->last_error = 'missing table'; return false; }
  };
  self::assertFalse(BotCounterStore::schemaReady($db));
 }
}
