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

	public function test_placeholder_slugs_are_never_sent_but_real_unsupported_names_are(): void {
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
		$items  = array( new InstalledSoftware( 'plugin', 'unsupported_4', '1.0', false ), new InstalledSoftware( 'plugin', 'unsupported-tools', '1.0', false ) );
		$runner = new DirectScanRunner( new DirectFeedClient( $http, $cache ) );
		$step   = $runner->step( $items, 0, 1790676000 );
		self::assertSame( 1, $http->calls, 'Only the real slug is looked up.' );
		$done = $runner->step( $items, $step->nextOffset, 1790676000 );
		self::assertTrue( $done->allFetched );
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
		$runner = new DirectScanRunner( new DirectFeedClient( $http, $cache ), provenance: static function () use ( &$calls ): string { ++$calls; return '1790676000:proof-v1'; }, stateStillMatches: static fn (): bool => true );
		$items  = array( new InstalledSoftware( 'plugin', 'sample', '1.0', false ) );
		$feed   = $runner->step( $items, 0, 1790676000 );
		self::assertNull( $feed->report );
		self::assertSame( 'provenance', $feed->phase );
		$proof = $runner->step( $items, 0, 1790676000, 'provenance' );
		self::assertSame( 1, $calls );
		self::assertSame( 'pass', $proof->report->results[0]->state );
		self::assertSame( '2026-09-29T10:00:00Z', $proof->report->results[0]->evidence['release_proof_at'] );
	}

	public function test_core_version_metadata_alone_cannot_produce_clean_verdict(): void {
		$http = new class implements HttpClient {
			public function get( string $url, int $maxBytes ): HttpResult {
				return new HttpResult( 200, '{"error":0,"updated":1790675900,"data":{"core":"7.1.2","vulnerability":null}}' );
			}
		};
		$cache = new class implements DirectFeedCache {
			private array $values = array();
			public function get( string $key ): ?array { return $this->values[ $key ] ?? null; }
			public function put( string $key, string $body, int $fetchedAt ): void { $this->values[ $key ] = array( 'body' => $body, 'fetched_at' => $fetchedAt ); }
		};
		$report = ( new DirectScanRunner( new DirectFeedClient( $http, $cache ) ) )->step( array( new InstalledSoftware( 'core', 'wordpress', '7.1.2', true ) ), 0, 1790676000 )->report;
		self::assertSame( 'unknown', $report->results[0]->state );
	}

	public function test_same_version_file_change_between_provenance_steps_invalidates_clean_result(): void {
		$http = new class implements HttpClient {
			public function get( string $url, int $maxBytes ): HttpResult {
				$slug = basename( rtrim( $url, '/' ) );
				return new HttpResult( 200, '{"error":0,"updated":1790675900,"data":{"plugin":"' . $slug . '","vulnerability":null}}' );
			}
		};
		$cache = new class implements DirectFeedCache {
			private array $values = array();
			public function get( string $key ): ?array { return $this->values[ $key ] ?? null; }
			public function put( string $key, string $body, int $fetchedAt ): void { $this->values[ $key ] = array( 'body' => $body, 'fetched_at' => $fetchedAt ); }
		};
		$state = array( 'first' => 'original', 'second' => 'original' );
		$runner = new DirectScanRunner(
			new DirectFeedClient( $http, $cache ),
			provenance: static fn ( InstalledSoftware $item ): string => $state[ $item->slug ],
			stateStillMatches: static function ( InstalledSoftware $item, string $proof ) use ( &$state ): bool { return $state[ $item->slug ] === $proof; }
		);
		$items = array( new InstalledSoftware( 'plugin', 'first', '1.0', false ), new InstalledSoftware( 'plugin', 'second', '1.0', false ) );
		$feed  = $runner->step( $items, 0, 1790676000 );
		$first = $runner->step( $items, 0, 1790676000, 'provenance', $feed->verified );
		$state['first'] = 'modified';
		$last = $runner->step( $items, $first->nextOffset, 1790676000, 'provenance', $first->verified );
		self::assertSame( array( 'unknown', 'pass' ), array_map( static fn ( $row ): string => $row->state, $last->report->results ) );
	}

	public function test_revoked_consent_stops_remaining_component_requests_in_batch(): void {
		$enabled = true;
		$http = new class( $enabled ) implements HttpClient {
			public int $calls = 0;
			public function __construct( private bool &$enabled ) {}
			public function get( string $url, int $maxBytes ): HttpResult {
				++$this->calls;
				$this->enabled = false;
				return new HttpResult( 0, '' );
			}
		};
		$cache = new class implements DirectFeedCache {
			public function get( string $key ): ?array { return null; }
			public function put( string $key, string $body, int $fetchedAt ): void {}
		};
		$runner = new DirectScanRunner( new DirectFeedClient( $http, $cache ), shouldContinue: static function () use ( &$enabled ): bool { return $enabled; } );
		$items = array( new InstalledSoftware( 'plugin', 'first', '1.0', false ), new InstalledSoftware( 'plugin', 'second', '1.0', false ) );
		$step = $runner->step( $items, 0, 1790676000 );
		self::assertSame( 1, $http->calls );
		self::assertNull( $step->report );
	}
}
