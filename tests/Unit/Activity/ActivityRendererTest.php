<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Tests\Unit\Activity;
use AmazingPlugins\Security\Activity\ActivityRenderer;
use PHPUnit\Framework\TestCase;
final class ActivityRendererTest extends TestCase {
    public function test_stored_values_are_escaped_and_empty_state_is_honest(): void {
        $view = new ActivityRenderer();
        $html=$view->render([['event'=>'<script>','target'=>'<img onerror=x>','actor_id'=>1,'user_id'=>2,'created_at'=>100]],1,'');
        self::assertStringNotContainsString('<script>', $html);
        self::assertStringContainsString('&lt;script&gt;', $html);
        self::assertStringNotContainsString('<img ', $html);
        self::assertStringContainsString('No recorded events', $view->render([],1,''));
        self::assertStringContainsString('best effort', $html);
    }
}
