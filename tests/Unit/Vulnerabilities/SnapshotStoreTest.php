<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Vulnerabilities;

use AmazingPlugins\Security\Integrity\OptionGateway;
use AmazingPlugins\Security\Vulnerabilities\Snapshot;
use AmazingPlugins\Security\Vulnerabilities\SnapshotResult;
use AmazingPlugins\Security\Vulnerabilities\WordPressSnapshotStore;
use PHPUnit\Framework\TestCase;

final class SnapshotStoreTest extends TestCase {
	public function test_unknown_verification_does_not_replace_the_last_accepted_snapshot(): void {
		$options = new class implements OptionGateway {
			public array $values = array();
			public function get( string $key ): mixed { return $this->values[ $key ] ?? null; }
			public function add( string $key, string $value ): bool { $this->values[ $key ] = $value; return true; }
			public function set( string $key, string $value ): bool { $this->values[ $key ] = $value; return true; }
			public function delete( string $key ): void { unset( $this->values[ $key ] ); }
			public function replaceIfSame( string $key, string $expected, string $replacement ): bool { return false; }
			public function deleteIfSame( string $key, string $expected ): bool { return false; }
		};
		$store = new WordPressSnapshotStore( $options );
		$good = new Snapshot( 7, '2026-09-29T02:00:00Z', '2026-09-30T02:00:00Z', str_repeat( 'a', 64 ), array() );
		$store->saveAccepted( new SnapshotResult( 'accepted', '', $good ) );
		$store->saveAccepted( new SnapshotResult( 'unknown', 'Signature failed.' ) );
		self::assertSame( 7, $store->latestAccepted()->sequence );
		self::assertCount( 1, $options->values );
	}
}
