<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Tests\Unit\Sessions;
use AmazingPlugins\Security\Sessions\SessionPolicy;
use PHPUnit\Framework\TestCase;
final class SessionPolicyTest extends TestCase {
    public function test_approving_cookie_tokens_must_match(): void {
        self::assertTrue(SessionPolicy::matchingTokens('same','same'));
        self::assertFalse(SessionPolicy::matchingTokens('admin-session','other-session'));
        self::assertFalse(SessionPolicy::matchingTokens('',''));
    }
    public function test_every_precondition_is_required(): void {
        self::assertTrue(SessionPolicy::allowed(true,true,true,true,true,true));
        for($i=0;$i<6;$i++){$args=array_fill(0,6,true);$args[$i]=false;self::assertFalse(SessionPolicy::allowed(...$args));}
    }
    public function test_view_exposes_only_creation_and_expiry_times(): void {
        $rows=SessionPolicy::safeRows([['login'=>100,'expiration'=>200,'ip'=>'secret-ip','ua'=>'secret-ua','token'=>'secret']]);
        self::assertSame([['login'=>100,'expiration'=>200]],$rows);
        self::assertCount(50,SessionPolicy::safeRows(array_fill(0,60,['login'=>100,'expiration'=>200])));
    }
}
