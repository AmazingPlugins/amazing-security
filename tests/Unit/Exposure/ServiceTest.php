<?php
namespace AmazingPlugins\Security\Tests\Unit\Exposure;

use AmazingPlugins\Security\Exposure\ExposureService;
use AmazingPlugins\Security\Exposure\ExposureScanner;
use AmazingPlugins\Security\Tests\Unit\Digest\MemoryOptions;
use PHPUnit\Framework\TestCase;
final class ServiceTest extends TestCase {
	private string $root;
	protected function setUp(): void {
		$this->root = sys_get_temp_dir() . '/amsec-exposure-state-' . bin2hex( random_bytes( 4 ) );
		mkdir( $this->root, 0700 );
		file_put_contents( $this->root . '/dummy.sql', 'INERT' );}
	protected function tearDown(): void {
		unlink( $this->root . '/dummy.sql' );
		rmdir( $this->root );}
	private function service( $o, $scanner = null ): ExposureService {
		return new ExposureService( $o, $scanner ?? new ExposureScanner(), fn( $alias )=>$this->root );}
	public function test_separate_root_reports_and_no_absolute_path_or_contents(): void {
		$o = new MemoryOptions();
		$s = $this->service( $o );
		foreach ( array( 'site', 'content', 'uploads' ) as $alias ) {
			self::assertSame( 'saved', $s->scan( $alias, 1000 ) );
		}self::assertCount( 3, $s->status()['reports'] );
		self::assertStringNotContainsString( $this->root, $o->values['amsec_exposure_state'] );
		self::assertStringNotContainsString( 'INERT', $o->values['amsec_exposure_state'] );
		self::assertSame( 'unsupported', $s->scan( '../other', 1001 ) );}
	public function test_failed_save_and_concurrent_cas_refuse_coverage_claim(): void {
		$o                     = new MemoryOptions();
		$s                     = $this->service( $o );
		$o->failExposureWrites = true;
		self::assertSame( 'failed', $s->scan( 'site', 1000 ) );
		self::assertArrayNotHasKey( 'amsec_exposure_state', $o->values );
		$o->failExposureWrites = false;
		$s->scan( 'site', 1000 );
		$stat = static function ( $p ) use ( $o ) {
			$o->values['amsec_exposure_state'] = 'concurrent';
			return lstat( $p );
		};
		self::assertSame( 'failed', $this->service( $o, new ExposureScanner( null, $stat ) )->scan( 'uploads', 1001 ) );
		self::assertSame( 'concurrent', $o->values['amsec_exposure_state'] );}
	public function test_impossible_counts_and_category_filename_corruption_are_invalid(): void {
		$o = new MemoryOptions();
		$s = $this->service( $o );
		$s->scan( 'site', 1000 );
		$good = json_decode( $o->values['amsec_exposure_state'], true );
		foreach ( array( 'counts', 'category', 'list' ) as $case ) {
			$state = $good;
			if ( $case === 'counts' ) {
				$state['reports']['site']['entries']     = 0;
				$state['reports']['site']['directories'] = 0;
			} elseif ( $case === 'category' ) {
				$state['reports']['site']['candidates'][0]['path']     = 'portrait.jpg';
				$state['reports']['site']['candidates'][0]['category'] = 'log';
			} else {
				$state['reports']['site']['candidates'] = array( 'bad' => $state['reports']['site']['candidates'][0] );
			}$o->values['amsec_exposure_state'] = json_encode( $state );
			self::assertSame( array( 'invalid' => true ), $s->status() );}}
	public function test_corrupt_or_oversized_state_is_invalid_and_locked_work_is_excluded(): void {
		$o = new MemoryOptions();
		$s = $this->service( $o );
		$s->scan( 'site', 1000 );
		$good = $o->values['amsec_exposure_state'];
		foreach ( array( 'bad', str_repeat( 'x', 262145 ) ) as $bad ) {
			$o->values['amsec_exposure_state'] = $bad;
			self::assertSame( array( 'invalid' => true ), $s->status() );
			self::assertSame( 'invalid', $s->scan( 'site', 1001 ) );
		}$o->values['amsec_exposure_state'] = $good;
		$state                              = json_decode( $good, true );
		$state['reports']['site']['candidates'][0]['path'] = '../outside.sql';
		$o->values['amsec_exposure_state']                 = json_encode( $state );
		self::assertSame( array( 'invalid' => true ), $s->status() );
		$o->values['amsec_exposure_lock'] = json_encode( array( 'expires' => time() + 60 ) );
		self::assertSame( 'busy', $s->scan( 'site', 1001 ) );}
}
