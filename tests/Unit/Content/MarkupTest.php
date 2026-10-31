<?php
namespace AmazingPlugins\Security\Tests\Unit\Content;

use AmazingPlugins\Security\Content\MarkupDetector;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
final class MarkupTest extends TestCase {
	public static function cases(): array {
		return array(
			'quoted fake anchor'       => array( "<div data-example=\"<a href='https://outside.invalid' style='display:none'>\">", array() ),
			'quoted fake script'       => array( "<div data-example=\"<script>location='https://outside.invalid';</script>\">", array() ),
			'template'                 => array( '<template><a href="javascript:example">x</a><script>location="https://outside.invalid";</script></template>', array() ),
			'nested template'          => array( '<template><template></template><a href="javascript:example">x</a></template>', array() ),
			'xmp'                      => array( '<xmp><a href="javascript:example">x</a></xmp>', array() ),
			'iframe'                   => array( '<iframe><a href="javascript:example">x</a></iframe>', array() ),
			'custom anchor'            => array( '<a-example href="https://outside.invalid" style="display:none">x</a-example>', array() ),
			'custom meta'              => array( '<meta-data http-equiv="refresh" content="0;url=https://outside.invalid">', array() ),
			'hidden external'          => array( '<a href="https://outside.invalid/path?token=private" style="display:none">x</a>', array( 'AS-HTML-001' ) ),
			'same host'                => array( '<a href="https://site.test/account" style="display:none">x</a>', array() ),
			'relative'                 => array( '<a href="/account" style="display:none">x</a>', array() ),
			'visible external'         => array( '<a href="https://outside.invalid">x</a>', array() ),
			'data style inert'         => array( '<a href="https://outside.invalid" data-style="display:none">x</a>', array() ),
			'comment'                  => array( '<!-- <a href="https://outside.invalid" style="display:none">x</a> -->', array() ),
			'textarea'                 => array( '<textarea><a href="https://outside.invalid" style="display:none">x</a></textarea>', array() ),
			'entity javascript'        => array( '<a href="java&#x73;cript:alert(1)">x</a>', array( 'AS-HTML-003' ) ),
			'data html'                => array( '<a href="data:text/html,&lt;script&gt;">x</a>', array( 'AS-HTML-003' ) ),
			'image data benign'        => array( '<a href="data:image/png;base64,AAAA">x</a>', array() ),
			'refresh external'         => array( '<meta http-equiv="refresh" content="0;url=https://outside.invalid/path">', array( 'AS-HTML-002' ) ),
			'refresh same host'        => array( '<meta http-equiv="refresh" content="1; URL=https://site.test/home">', array() ),
			'refresh fake text'        => array( '<div data-content="0;url=https://outside.invalid">x</div>', array() ),
			'literal redirect'         => array( '<script>window.location.href="https://outside.invalid/";</script>', array( 'AS-JS-001' ) ),
			'replace redirect'         => array( "<script>location.replace('https://outside.invalid/');</script>", array( 'AS-JS-001' ) ),
			'same host redirect'       => array( '<script>location="https://site.test/home";</script>', array() ),
			'json script'              => array( '<script type="application/json">location="https://outside.invalid/";</script>', array() ),
			'documentation string'     => array( '<script>const example = \'location="https://outside.invalid/";\';</script>', array() ),
			'commented script'         => array( '<script>// location="https://outside.invalid/";</script>', array() ),
			'comment script inert'     => array( '<!-- <script>location="https://outside.invalid/";</script> -->', array() ),
			'textarea script inert'    => array( '<textarea><script>location="https://outside.invalid/";</script></textarea>', array() ),
			'boolean src inert'        => array( '<script src>location="https://outside.invalid/";</script>', array() ),
			'src script body inert'    => array( '<script src="/safe.js">location="https://outside.invalid/";</script>', array() ),
			'style text inert'         => array( '<style>.sample{content:\'<a href="https://outside.invalid" style="display:none">x</a>\'}</style>', array() ),
			'unclosed textarea'        => array( '<textarea><a href="https://outside.invalid" style="display:none">x</a>', array() ),
			'protocol relative hidden' => array( '<a href="//outside.invalid" style="visibility:hidden">x</a>', array( 'AS-HTML-001' ) ),
			'entity hidden host'       => array( '<a href="https:&#47;&#47;outside.invalid" style="display:none!important">x</a>', array( 'AS-HTML-001' ) ),
			'hidden external frame'    => array( '<iframe src="https://outside.invalid/path" style="display:none"></iframe>', array( 'AS-HTML-004' ) ),
			'visible external frame'   => array( '<iframe src="https://outside.invalid/path"></iframe>', array() ),
			'hidden same host frame'   => array( '<iframe src="https://site.test/embed" style="display:none"></iframe>', array() ),
		);}
	#[DataProvider( 'cases' )] public function test_markup( string $body, array $expected ): void {
		$hits = ( new MarkupDetector( 'site.test' ) )->match( $body );
		self::assertSame( $expected, array_column( $hits, 'rule' ) );
		self::assertStringNotContainsString( 'outside.invalid', json_encode( $hits ) );
		self::assertStringNotContainsString( 'private', json_encode( $hits ) );}
	public function test_offsets_and_byte_limit_are_preserved(): void {
		$d = new MarkupDetector( 'site.test' );
		self::assertSame( 4, $d->match( "\n\n<!-- fixture -->\n<a href='https://outside.invalid' style='display:none'>x</a>" )[0]['line'] );
		$this->expectException( \RuntimeException::class );
		$d->match( str_repeat( 'x', 131073 ) );}
}
