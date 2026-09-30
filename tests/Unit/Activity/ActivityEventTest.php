<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Tests\Unit\Activity;
use AmazingPlugins\Security\Activity\ActivityEvent;
use PHPUnit\Framework\TestCase;
final class ActivityEventTest extends TestCase {
    public function test_fixed_schema_rejects_unknown_event_and_secret_metadata(): void {
        $this->expectException(\InvalidArgumentException::class);
        new ActivityEvent('password_secret', 1, 2, 'secret', 100);
    }
    public function test_target_is_bounded_and_cannot_contain_control_characters(): void {
        $this->expectException(\InvalidArgumentException::class);
        new ActivityEvent('plugin_activated',1,0,"x\nsecret",100);
    }
    public function test_event_stores_only_fixed_fields(): void {
        $event=new ActivityEvent('user_role_changed',1,2,'administrator',100);
        self::assertSame(['event'=>'user_role_changed','actor_id'=>1,'user_id'=>2,'target'=>'administrator','created_at'=>100],$event->row());
    }
}
