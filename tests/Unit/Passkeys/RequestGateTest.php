<?php
namespace AmazingPlugins\Security\Tests\Unit\Passkeys;
use PHPUnit\Framework\TestCase;
use AmazingPlugins\Security\Passkeys\{PasskeyRequestGate,PasskeyContext};
final class RequestGateTest extends TestCase {
 public function testMutationsRequireExactHttpsOriginPostAndMatchedOwnSession():void {
 $ctx=PasskeyContext::fromSiteUrl('https://example.com:8443');$server=['REQUEST_METHOD'=>'POST','HTTP_ORIGIN'=>'https://example.com:8443'];self::assertTrue(PasskeyRequestGate::request($ctx,$server,true));foreach([['REQUEST_METHOD'=>'GET'],['HTTP_ORIGIN'=>'https://example.com'],['HTTP_ORIGIN'=>'https://evilexample.com:8443'],['HTTP_ORIGIN'=>[]],['HTTP_ORIGIN'=>"https://example.com:8443\n"]] as $bad)self::assertFalse(PasskeyRequestGate::request($ctx,array_replace($server,$bad),true));self::assertFalse(PasskeyRequestGate::request($ctx,$server,false));
 self::assertTrue(PasskeyRequestGate::own(4,4,'token','token',true,true));foreach([[0,0,'token','token',true,true],[4,5,'token','token',true,true],[4,4,'','',true,true],[4,4,'token','other',true,true],[4,4,'token','token',false,true],[4,4,'token','token',true,false]] as $args)self::assertFalse(PasskeyRequestGate::own(...$args));
 }
}
