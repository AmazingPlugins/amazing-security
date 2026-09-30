<?php
namespace AmazingPlugins\Security\Tests\Unit\Content;
use AmazingPlugins\Security\Content\MarkupDetector;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
final class MarkupTest extends TestCase {
 public static function cases():array{return [
 'quoted fake anchor'=>["<div data-example=\"<a href='https://outside.invalid' style='display:none'>\">",[]],
 'quoted fake script'=>["<div data-example=\"<script>location='https://outside.invalid';</script>\">",[]],
 'template'=>['<template><a href="javascript:example">x</a><script>location="https://outside.invalid";</script></template>',[]],
 'nested template'=>['<template><template></template><a href="javascript:example">x</a></template>',[]],
 'xmp'=>['<xmp><a href="javascript:example">x</a></xmp>',[]],
 'iframe'=>['<iframe><a href="javascript:example">x</a></iframe>',[]],
 'custom anchor'=>['<a-example href="https://outside.invalid" style="display:none">x</a-example>',[]],
 'custom meta'=>['<meta-data http-equiv="refresh" content="0;url=https://outside.invalid">',[]],
 'hidden external'=>['<a href="https://outside.invalid/path?token=private" style="display:none">x</a>',['AS-HTML-001']],
 'same host'=>['<a href="https://site.test/account" style="display:none">x</a>',[]],
 'relative'=>['<a href="/account" style="display:none">x</a>',[]],
 'visible external'=>['<a href="https://outside.invalid">x</a>',[]],
 'data style inert'=>['<a href="https://outside.invalid" data-style="display:none">x</a>',[]],
 'comment'=>['<!-- <a href="https://outside.invalid" style="display:none">x</a> -->',[]],
 'textarea'=>['<textarea><a href="https://outside.invalid" style="display:none">x</a></textarea>',[]],
 'entity javascript'=>['<a href="java&#x73;cript:alert(1)">x</a>',['AS-HTML-003']],
 'data html'=>['<a href="data:text/html,&lt;script&gt;">x</a>',['AS-HTML-003']],
 'image data benign'=>['<a href="data:image/png;base64,AAAA">x</a>',[]],
 'refresh external'=>['<meta http-equiv="refresh" content="0;url=https://outside.invalid/path">',['AS-HTML-002']],
 'refresh same host'=>['<meta http-equiv="refresh" content="1; URL=https://site.test/home">',[]],
 'refresh fake text'=>['<div data-content="0;url=https://outside.invalid">x</div>',[]],
 'literal redirect'=>['<script>window.location.href="https://outside.invalid/";</script>',['AS-JS-001']],
 'replace redirect'=>["<script>location.replace('https://outside.invalid/');</script>",['AS-JS-001']],
 'same host redirect'=>['<script>location="https://site.test/home";</script>',[]],
 'json script'=>['<script type="application/json">location="https://outside.invalid/";</script>',[]],
 'documentation string'=>['<script>const example = \'location="https://outside.invalid/";\';</script>',[]],
 'commented script'=>['<script>// location="https://outside.invalid/";</script>',[]],
 'comment script inert'=>['<!-- <script>location="https://outside.invalid/";</script> -->',[]],
 'textarea script inert'=>['<textarea><script>location="https://outside.invalid/";</script></textarea>',[]],
 'boolean src inert'=>['<script src>location="https://outside.invalid/";</script>',[]],
 'src script body inert'=>['<script src="/safe.js">location="https://outside.invalid/";</script>',[]],
 'style text inert'=>['<style>.sample{content:\'<a href="https://outside.invalid" style="display:none">x</a>\'}</style>',[]],
 'unclosed textarea'=>['<textarea><a href="https://outside.invalid" style="display:none">x</a>',[]],
 'protocol relative hidden'=>['<a href="//outside.invalid" style="visibility:hidden">x</a>',['AS-HTML-001']],
 'entity hidden host'=>['<a href="https:&#47;&#47;outside.invalid" style="display:none!important">x</a>',['AS-HTML-001']],
 ];}
 #[DataProvider('cases')] public function test_markup(string $body,array $expected):void{$hits=(new MarkupDetector('site.test'))->match($body);self::assertSame($expected,array_column($hits,'rule'));self::assertStringNotContainsString('outside.invalid',json_encode($hits));self::assertStringNotContainsString('private',json_encode($hits));}
 public function test_offsets_and_byte_limit_are_preserved():void{$d=new MarkupDetector('site.test');self::assertSame(4,$d->match("\n\n<!-- fixture -->\n<a href='https://outside.invalid' style='display:none'>x</a>")[0]['line']);$this->expectException(\RuntimeException::class);$d->match(str_repeat('x',131073));}
}
