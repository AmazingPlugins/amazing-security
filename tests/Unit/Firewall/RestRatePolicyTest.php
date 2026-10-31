<?php
namespace AmazingPlugins\Security\Tests\Unit\Firewall;

use AmazingPlugins\Security\Firewall\RestRatePolicy;
use PHPUnit\Framework\TestCase;
final class RestRatePolicyTest extends TestCase {
	public function test_schema_defaults_and_corrupt_state(): void {
		$p = new RestRatePolicy();
		self::assertSame( 'off', $p->read( null )['mode'] );
		$valid = array(
			'version'    => 1,
			'mode'       => 'observe',
			'exemptions' => array( 'users-read' ),
			'revision'   => str_repeat( 'a', 32 ),
		);
		self::assertSame( $valid, $p->read( json_encode( $valid ) ) );
		foreach ( array( 'bad', str_repeat( 'x', 4097 ), json_encode( array_replace( $valid, array( 'exemptions' => array( 'unknown' ) ) ) ), json_encode( array_replace( $valid, array( 'exemptions' => array( 'users-read', 'users-read' ) ) ) ), json_encode( array_replace( $valid, array( 'mode' => 'auto' ) ) ), json_encode( array_replace( $valid, array( 'revision' => 'bad' ) ) ) ) as $raw ) {
			self::assertNull( $p->read( $raw ) );}}
	public function test_native_route_method_auth_and_prior_result_boundaries(): void {
		$p = new RestRatePolicy();
		self::assertSame( 'users-read', $p->target( '/wp/v2/users', 'GET', false, null ) );
		self::assertSame( 'users-read', $p->target( '/wp/v2/users/123/', 'GET', false, null ) );
		self::assertSame( 'comments-create', $p->target( '/wp/v2/comments/', 'POST', false, null ) );
		foreach ( array( array( '/wp/v2/users', 'POST', false, null ), array( '/wp/v2/users', 'GET', true, null ), array( '/wp/v2/users', 'GET', false, false ), array( '/wp/v2/users', 'GET', false, array( 'prior' ) ), array( '/wp/v2/users/foo', 'GET', false, null ), array( '/wp/v2/comments/2', 'POST', false, null ), array( '/wc/store/v1/cart', 'POST', false, null ), array( '/contact-form-7/v1/contact-forms/1/feedback', 'POST', false, null ), array( '/wp/v2/users', 'OPTIONS', false, null ) ) as $args ) {
			self::assertNull( $p->target( ...$args ) );}}
	public function test_equivalent_native_case_long_numeric_and_newline_routes(): void {
		$p = new RestRatePolicy();
		foreach ( array( '/wp/v2/USERS', '/WP/V2/users/000000000001', '/wp/v2/users/' . str_repeat( '0', 120 ) . '1', "/wp/v2/users\n" ) as $route ) {
			self::assertSame( 'users-read', $p->target( $route, 'GET', false, null ) );
		}foreach ( array( '/wp/v2/COMMENTS', "/wp/v2/comments\n" ) as $route ) {
			self::assertSame( 'comments-create', $p->target( $route, 'POST', false, null ) );}}
	public function test_observe_block_threshold_exemptions_and_unknown_fail_open(): void {
		$p = new RestRatePolicy();
		foreach ( array( 'off', 'observe' ) as $mode ) {
			self::assertFalse( $p->reject( $mode, 'comments-create', array(), 21 ) );
		}self::assertFalse( $p->reject( 'block', 'comments-create', array(), 20 ) );
		self::assertTrue( $p->reject( 'block', 'comments-create', array(), 21 ) );
		self::assertFalse( $p->reject( 'block', 'users-read', array(), 60 ) );
		self::assertTrue( $p->reject( 'block', 'users-read', array(), 61 ) );
		self::assertFalse( $p->reject( 'block', 'users-read', array( 'users-read' ), 61 ) );
		self::assertFalse( $p->reject( 'block', 'users-read', array(), null ) );
		self::assertFalse( $p->reject( 'block', 'custom', array(), 61 ) );}
}
