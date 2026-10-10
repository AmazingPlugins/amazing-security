<?php
namespace AmazingPlugins\Security\Checks {
	function get_option( string $name, $default = false ) {
		return $GLOBALS['amsec_test_options'][ $name ] ?? $default;
	}
}
namespace AmazingPlugins\Security\Tests\Unit\Checks {
	use AmazingPlugins\Security\Checks\FollowUpCheck;
	use PHPUnit\Framework\TestCase;

	final class SuspiciousFilesSnapshotTest extends TestCase {
		protected function tearDown(): void {
			unset( $GLOBALS['amsec_test_options'] );
		}

		/** @param list<array<string,string>> $findings */
		private function store( string $state, bool $partial, array $findings ): void {
			$GLOBALS['amsec_test_options']['amazing_security_file_scan_completed'] = json_encode(
				array(
					'scan_id'     => 'scan-1',
					'state'       => $state,
					'finished_at' => '2026-10-10T00:00:00+00:00',
					'partial'     => $partial,
					'processed'   => 10,
					'bytes'       => 100,
					'unknown'     => 0,
					'excluded'    => 0,
					'extra'       => 0,
					'verified'    => 0,
					'scanned'     => 9,
					'omitted'     => 0,
					'findings'    => $findings,
				)
			);
		}

		public function test_unreadable_files_are_a_coverage_gap_not_a_rule_match(): void {
			$this->store( 'inconclusive', false, array( array( 'state' => 'inconclusive', 'kind' => 'unscanned', 'reason' => 'budget' ) ) );
			self::assertSame( array( 'stored' => 'partial', 'found' => 0 ), FollowUpCheck::suspiciousFiles() );
		}

		public function test_a_real_rule_match_is_still_reported(): void {
			$this->store(
				'warn',
				false,
				array(
					array( 'state' => 'inconclusive', 'kind' => 'unscanned', 'reason' => 'budget' ),
					array( 'state' => 'warn', 'kind' => 'suspicious', 'rule_id' => 'AS-PHP-001' ),
				)
			);
			self::assertSame( array( 'stored' => 'found', 'found' => 1 ), FollowUpCheck::suspiciousFiles() );
		}

		public function test_a_finished_scan_with_no_findings_is_clean(): void {
			$this->store( 'pass', false, array() );
			self::assertSame( array( 'stored' => 'clean', 'found' => 0 ), FollowUpCheck::suspiciousFiles() );
		}
	}
}
