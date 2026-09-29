<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Vulnerabilities;

use AmazingPlugins\Security\Integrity\HttpClient;
use AmazingPlugins\Security\Integrity\HttpResult;
use AmazingPlugins\Security\Vulnerabilities\DirectFeedCache;
use AmazingPlugins\Security\Vulnerabilities\DirectFeedClient;
use AmazingPlugins\Security\Vulnerabilities\DirectScanRunner;
use AmazingPlugins\Security\Vulnerabilities\InstalledSoftware;
use PHPUnit\Framework\TestCase;

final class DirectScanRunnerTest extends TestCase {
	public function test_work_is_split_into_bounded_steps_and_completed_report_uses_cache(): void {
		$http = new class implements HttpClient {
			public int $calls = 0;
			public function get( string $url, int $maxBytes ): HttpResult {
				++$this->calls;
				$slug = trim( basename( rtrim( $url, '/' ) ) );
				return new HttpResult( 200, json_encode( array( 'error' => 0, 'message' => null, 'updated' => 1790675900, 'data' => array( 'plugin' => $slug, 'vulnerability' => null ) ) ) );
			}
		};
		$cache = new class implements DirectFeedCache {
			private array $values = array();
			public function get( string $key ): ?array { return $this->values[ $key ] ?? null; }
			public function put( string $key, string $body, int $fetchedAt ): void { $this->values[ $key ] = array( 'body' => $body, 'fetched_at' => $fetchedAt ); }
		};
		$items = array();
		foreach ( array( 'one', 'two', 'three', 'four' ) as $slug ) {
			$items[] = new InstalledSoftware( 'plugin', $slug, '1.0', false );
		}
		$runner = new DirectScanRunner( new DirectFeedClient( $http, $cache ) );
		$first  = $runner->step( $items, 0, 1790676000 );
		self::assertSame( 3, $first->nextOffset );
		self::assertNull( $first->report );
		$second = $runner->step( $items, $first->nextOffset, 1790676000 );
		self::assertSame( 4, $second->nextOffset );
		self::assertNotNull( $second->report );
		self::assertTrue( $second->allFetched );
		self::assertSame( 4, $http->calls );
		self::assertSame( array( 'unknown', 'unknown', 'unknown', 'unknown' ), array_map( static fn ( $row ): string => $row->state, $second->report->results ) );
	}

	public function test_optional_local_release_proof_runs_in_a_separate_step_before_clean_verdict(): void {
		$http = new class implements HttpClient {
			public function get( string $url, int $maxBytes ): HttpResult {
				return new HttpResult( 200, '{"error":0,"message":null,"updated":1790675900,"data":{"plugin":"sample","vulnerability":null}}' );
			}
		};
		$cache = new class implements DirectFeedCache {
			private array $values = array();
			public function get( string $key ): ?array { return $this->values[ $key ] ?? null; }
			public function put( string $key, string $body, int $fetchedAt ): void { $this->values[ $key ] = array( 'body' => $body, 'fetched_at' => $fetchedAt ); }
		};
		$calls  = 0;
		$runner = new DirectScanRunner( new DirectFeedClient( $http, $cache ), provenance: static function () use ( &$calls ): bool { ++$calls; return true; } );
		$items  = array( new InstalledSoftware( 'plugin', 'sample', '1.0', false ) );
		$feed   = $runner->step( $items, 0, 1790676000 );
		self::assertNull( $feed->report );
		self::assertSame( 'provenance', $feed->phase );
		$proof = $runner->step( $items, 0, 1790676000, 'provenance' );
		self::assertSame( 1, $calls );
		self::assertSame( 'pass', $proof->report->results[0]->state );
	}
}
