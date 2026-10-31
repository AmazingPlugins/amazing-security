<?php
namespace AmazingPlugins\Security\Tests\Unit\Firewall;

use AmazingPlugins\Security\Firewall\RestRateSettingsService;
use AmazingPlugins\Security\Tests\Unit\Digest\MemoryOptions;
use PHPUnit\Framework\TestCase;
final class RestRateSettingsServiceTest extends TestCase {
	public function test_exact_policy_approval_new_revision_and_recovery(): void {
		$o  = new MemoryOptions();
		$s  = new RestRateSettingsService( $o );
		$fp = $s->fingerprint();
		self::assertSame( 'saved', $s->apply( $fp, 'observe', array() ) );
		$old = $s->status()['revision'];
		self::assertSame( 'changed', $s->apply( $fp, 'block', array() ) );
		self::assertSame( 'saved', $s->apply( $s->fingerprint(), 'block', array( 'users-read' ) ) );
		self::assertNotSame( $old, $s->status()['revision'] );
		$o->values['amsec_rest_rate_policy'] = 'corrupt';
		self::assertSame( array( 'invalid' => true ), $s->status() );
		self::assertSame( 'invalid', $s->apply( $s->fingerprint(), 'block', array() ) );
		self::assertTrue( $s->disable() );
		self::assertSame( 'off', $s->status()['mode'] );
		self::assertSame( array(), $s->status()['exemptions'] );}
	public function test_invalid_input_failed_write_and_cas_are_refused(): void {
		$o = new MemoryOptions();
		$s = new RestRateSettingsService( $o );
		self::assertSame( 'unsupported', $s->apply( $s->fingerprint(), 'block', array( 'custom' ) ) );
		$o->failRestRateWrites = true;
		self::assertSame( 'failed', $s->apply( $s->fingerprint(), 'block', array() ) );
		self::assertArrayNotHasKey( 'amsec_rest_rate_policy', $o->values );
		$o->failRestRateWrites = false;
		self::assertSame( 'saved', $s->apply( $s->fingerprint(), 'observe', array() ) );
		$before                = $o->values['amsec_rest_rate_policy'];
		$o->failRestRateWrites = true;
		self::assertSame( 'failed', $s->apply( $s->fingerprint(), 'block', array() ) );
		self::assertSame( $before, $o->values['amsec_rest_rate_policy'] );}
}
