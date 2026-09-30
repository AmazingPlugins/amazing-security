<?php
namespace AmazingPlugins\Security\Tests\Unit\Bots;
use AmazingPlugins\Security\Bots\BotPolicy;
use PHPUnit\Framework\TestCase;
final class BotPolicyTest extends TestCase {
 public function test_missing_or_empty_trap_keeps_legacy_forms_working(): void {
  self::assertFalse(BotPolicy::trapSuspicious(null));self::assertFalse(BotPolicy::trapSuspicious(''));self::assertFalse(BotPolicy::trapSuspicious('  '));self::assertTrue(BotPolicy::trapSuspicious('filled'));self::assertTrue(BotPolicy::trapSuspicious([]));
 }
 public function test_only_opted_in_block_mode_rejects_suspicion_or_rate_excess(): void {
  self::assertTrue(BotPolicy::reject('block',true,1,20));self::assertTrue(BotPolicy::reject('block',false,21,20));self::assertFalse(BotPolicy::reject('block',false,20,20));self::assertFalse(BotPolicy::reject('observe',true,99,20));self::assertFalse(BotPolicy::reject('off',true,99,20));self::assertFalse(BotPolicy::reject('block',false,null,20));
 }
}
