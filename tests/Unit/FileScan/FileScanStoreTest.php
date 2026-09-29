<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\FileScan;

use AmazingPlugins\Security\FileScan\FileScanCursor;
use AmazingPlugins\Security\FileScan\FileScanReport;
use AmazingPlugins\Security\FileScan\FileScanStep;
use AmazingPlugins\Security\FileScan\WordPressFileScanStore;
use AmazingPlugins\Security\Integrity\OptionGateway;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class FileScanStoreTest extends TestCase {
	private function options(): OptionGateway {
		return new class implements OptionGateway {
			public array $values = array();
			public bool $failNextCas = false;
			public function get( string $key ): mixed { return $this->values[ $key ] ?? null; }
			public function add( string $key, string $value ): bool { if ( isset( $this->values[ $key ] ) ) { return false; } $this->values[ $key ] = $value; return true; }
			public function set( string $key, string $value ): bool { $this->values[ $key ] = $value; return true; }
			public function delete( string $key ): void { unset( $this->values[ $key ] ); }
			public function replaceIfSame( string $key, string $expected, string $replacement ): bool { if ( $this->failNextCas ) { $this->failNextCas = false; return false; } if ( ( $this->values[ $key ] ?? null ) !== $expected || $expected === $replacement ) { return false; } $this->values[ $key ] = $replacement; return true; }
			public function deleteIfSame( string $key, string $expected ): bool { if ( ( $this->values[ $key ] ?? null ) !== $expected ) { return false; } unset( $this->values[ $key ] ); return true; }
		};
	}

	public function test_partial_run_preserves_completed_warnings(): void {
		$options = $this->options();
		$store = new WordPressFileScanStore( $options );
		$old = new FileScanCursor( 'old' );
		$old->finished = true;
		$old->findings[] = array( 'id' => 'finding-1', 'state' => 'warn', 'kind' => 'suspected', 'path' => 'demo.php', 'rule_id' => 'AS-PHP-001', 'version' => '1', 'line' => 1, 'reason' => '', 'summary' => 'Suspected code', 'tested_at' => gmdate( 'c' ) );
		self::assertTrue( $store->begin( 'old', $old ) );
		$store->saveProgress( 'old', new FileScanStep( $old, true ) );
		$store->complete( 'old', FileScanReport::fromCursor( $old ) );
		self::assertSame( 'warn', $store->latestCompleted()->state );
		self::assertSame( 'warn', $store->historicalWarnings()[0]->state );
		$new = new FileScanCursor( 'new' );
		self::assertTrue( $store->begin( 'new', $new ) );
		$new->partial = true;
		$new->finished = true;
		$store->saveProgress( 'new', new FileScanStep( $new, true ) );
		self::assertSame( 'warn', $store->latestCompleted()->state );
		self::assertSame( 'inconclusive', $store->latestProgress()->cursor->state() );
	}

	public function test_compare_and_swap_rejects_second_worker(): void {
		$options = $this->options();
		$one = new WordPressFileScanStore( $options );
		$two = new WordPressFileScanStore( $options );
		$cursor = new FileScanCursor( 'scan-1' );
		self::assertTrue( $one->begin( 'scan-1', $cursor ) );
		self::assertFalse( $two->begin( 'scan-2', new FileScanCursor( 'scan-2' ) ) );
		$cursor->processed = 1;
		$options->failNextCas = true;
		$this->expectException( RuntimeException::class );
		$one->saveProgress( 'scan-1', new FileScanStep( $cursor, false ) );
	}

	public function test_notes_are_bounded_and_do_not_remove_findings(): void {
		$store = new WordPressFileScanStore( $this->options() );
		$id = str_repeat( 'a', 32 );
		self::assertTrue( $store->saveNote( $id, 'Reviewed with developer.' ) );
		self::assertTrue( $store->saveNote( $id, 'Reviewed with developer.' ) );
		self::assertSame( 'Reviewed with developer.', $store->notes()[ $id ] );
		self::assertFalse( $store->saveNote( $id, str_repeat( 'x', 501 ) ) );
		self::assertSame( 'Reviewed with developer.', $store->notes()[ $id ] );
	}
}
