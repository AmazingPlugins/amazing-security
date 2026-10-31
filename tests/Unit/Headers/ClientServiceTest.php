<?php
namespace AmazingPlugins\Security\Tests\Unit\Headers;

use AmazingPlugins\Security\Headers\{HttpHeaderClient, HeaderClient, HeaderAssessment, HeaderService};
use AmazingPlugins\Security\Tests\Unit\Digest\MemoryOptions;
use PHPUnit\Framework\TestCase;
final class ClientServiceTest extends TestCase {
	public function test_anonymous_head_without_redirects_and_private_refusal(): void {
		$calls   = 0;
		$request = static function ( $url, $args ) use ( &$calls ) {
			++$calls;
			self::assertSame( 'https://example.org/blog/', $url );
			self::assertSame( 0, $args['redirection'] );
			self::assertSame( 5, $args['timeout'] );
			self::assertTrue( $args['sslverify'] );
			self::assertArrayNotHasKey( 'cookies', $args );
			return array(
				'response' => array( 'code' => 200 ),
				'headers'  => array(
					'content-type'    => 'text/html',
					'x-frame-options' => 'DENY',
					'set-cookie'      => 'PRIVATE',
				),
			);
		};
		$c       = new HttpHeaderClient( $request, static fn()=>array( '8.8.8.8' ) );
		self::assertSame( 'unknown', ( new HttpHeaderClient( $request, static fn()=>array( '8.8.8.8', '10.0.0.1' ) ) )->fetch( 'https://example.org/' )['state'] );
		self::assertSame( 'unknown', ( new HttpHeaderClient( $request, static fn()=>array() ) )->fetch( 'https://example.org/' )['state'] );
		self::assertSame( 0, $calls );
		self::assertSame( 'recognized', $c->fetch( 'https://example.org/blog/' )['headers']['framing'] );
		self::assertSame( 'unknown', $c->fetch( 'http://169.254.169.254/' )['state'] );
		self::assertSame( 1, $calls );}
	public function test_error_redirect_and_exception_are_unknown(): void {
		foreach ( array( 'error', 'redirect', 'exception' ) as $case ) {
			$request = static function ( $url, $args ) use ( $case ) {
				if ( $case === 'exception' ) {
					throw new \RuntimeException( 'SECRET' );
				}return $case === 'error' ? new \stdClass() : array(
					'response' => array( 'code' => 301 ),
					'headers'  => array( 'content-type' => 'text/html' ),
				);
			};
			self::assertSame( 'unknown', ( new HttpHeaderClient( $request, static fn()=>array( '8.8.8.8' ) ) )->fetch( 'https://example.org/' )['state'] );}}
	private function client( bool &$unknown, int &$calls, ?\Closure $after = null ): HeaderClient {
		return new class($unknown,$calls,$after) implements HeaderClient{public function __construct( private bool &$unknown, private int &$calls, private ?\Closure $after ) {}public function fetch( string $url ): array {
				++$this->calls;
				if ( $this->after ) {
					( $this->after )();
				}return $this->unknown ? ( new HeaderAssessment() )->unknown() : ( new HeaderAssessment() )->parse( 200, array( 'content-type' => array( 'text/html' ) ), true );
		}};}
	public function test_history_cooldown_changed_home_and_redaction(): void {
		$o       = new MemoryOptions();
		$home    = 'https://example.org/';
		$unknown = false;
		$calls   = 0;
		$s       = new HeaderService(
			$o,
			$this->client( $unknown, $calls ),
			static function () use ( &$home ) {
				return $home;
			}
		);
		$fp      = hash( 'sha256', $home );
		self::assertSame( 'saved', $s->check( $fp, 1000 ) );
		$good = $s->status()['last_good'];
		self::assertSame( 'cached', $s->check( $fp, 1001 ) );
		self::assertSame( 1, $calls );
		$unknown = true;
		self::assertSame( 'saved', $s->check( $fp, 1600 ) );
		self::assertSame( $good, $s->status()['last_good'] );
		self::assertSame( 'unknown', $s->status()['latest']['result']['state'] );
		self::assertStringNotContainsString( $home, $o->values['amsec_headers_state'] );
		self::assertSame( 'failed', $s->check( $fp, 999 ) );
		$changed = new HeaderService(
			$o,
			$this->client(
				$unknown,
				$calls,
				static function () use ( &$home ) {
					$home = 'https://changed.org/';
				}
			),
			static function () use ( &$home ) {
				return $home;
			}
		);
		self::assertSame( 'changed', $changed->check( $fp, 2200 ) );
		self::assertSame( $good, $s->status()['last_good'] );}
	public function test_failed_write_cas_and_corrupt_history_are_refused(): void {
		$o       = new MemoryOptions();
		$home    = 'https://example.org/';
		$unknown = false;
		$calls   = 0;
		$s       = new HeaderService( $o, $this->client( $unknown, $calls ), static fn()=>$home );
		$fp      = hash( 'sha256', $home );
		self::assertSame( 'saved', $s->check( $fp, 1000 ) );
		$before = $o->values['amsec_headers_state'];
		$c      = $this->client(
			$unknown,
			$calls,
			static function () use ( $o ) {
				$o->values['amsec_headers_state'] = 'concurrent';
			}
		);
		self::assertSame( 'failed', ( new HeaderService( $o, $c, static fn()=>$home ) )->check( $fp, 1600 ) );
		self::assertSame( 'concurrent', $o->values['amsec_headers_state'] );
		$bad                              = json_decode( $before, true );
		$bad['last_good']                 = null;
		$o->values['amsec_headers_state'] = json_encode( $bad );
		self::assertSame( array( 'invalid' => true ), $s->status() );
		self::assertSame( 'invalid', $s->check( $fp, 2200 ) );
		$o->values['amsec_headers_state'] = $before;
		$o->failHeaderWrites              = true;
		self::assertSame( 'failed', $s->check( $fp, 2200 ) );
		self::assertSame( $before, $o->values['amsec_headers_state'] );}
}
