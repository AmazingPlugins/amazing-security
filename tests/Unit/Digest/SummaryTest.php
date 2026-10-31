<?php
namespace AmazingPlugins\Security\Tests\Unit\Digest;

use AmazingPlugins\Security\Digest\DigestSummary;
use PHPUnit\Framework\TestCase;
final class SummaryTest extends TestCase {
	public function test_initial_summary_has_counts_and_coverage_without_sensitive_metadata(): void {
		$summary = DigestSummary::build(
			array(
				'hardening' => array(
					'at'      => 1000,
					'partial' => true,
					'unknown' => 2,
					'rows'    => array(
						array(
							'state'   => 'warn',
							'id'      => 'secret-path',
							'summary' => 'SECRET',
							'email'   => 'alice@example.test',
						),
					),
				),
			),
			array(
				'available' => true,
				'changes'   => 3,
				'blocked'   => 4,
			),
			null,
			1000
		);
		self::assertStringContainsString( 'Initial snapshot', $summary['body'] );
		self::assertStringContainsString( 'partial', $summary['body'] );
		self::assertStringContainsString( 'missing', $summary['body'] );
		self::assertStringContainsString( '4 recorded blocked login requests', $summary['body'] );
		self::assertStringNotContainsString( 'SECRET', $summary['body'] );
		self::assertStringNotContainsString( 'secret-path', json_encode( $summary ) );
		self::assertStringNotContainsString( 'alice@', json_encode( $summary ) );
	}
	public function test_partial_reports_retain_accepted_identities_and_stale_does_not_imply_resolution(): void {
		$first   = DigestSummary::build(
			array(
				'hardening' => array(
					'at'   => 1000,
					'rows' => array(
						array(
							'state' => 'warn',
							'id'    => 'one',
						),
					),
				),
			),
			array(),
			null,
			1000
		);
		$partial = DigestSummary::build(
			array(
				'hardening' => array(
					'at'      => 2000,
					'partial' => true,
					'rows'    => array(
						array(
							'state' => 'warn',
							'id'    => 'two',
						),
					),
				),
			),
			array(),
			$first['snapshot'],
			2000
		);
		self::assertCount( 2, $partial['snapshot']['identities']['hardening'] );
		self::assertStringContainsString( '1 newly observed', $partial['body'] );
		$again = DigestSummary::build(
			array(
				'hardening' => array(
					'at'   => 1000,
					'rows' => array(
						array(
							'state' => 'warn',
							'id'    => 'one',
						),
					),
				),
			),
			array(),
			$partial['snapshot'],
			700000
		);
		self::assertStringContainsString( 'stale', $again['body'] );
		self::assertStringContainsString( '0 newly observed', $again['body'] );
		self::assertCount( 2, $again['snapshot']['identities']['hardening'] );
	}
	public function test_report_and_baseline_budgets_are_explicit(): void {
		$rows    = array_map(
			static fn( $n )=>array(
				'state' => 'warn',
				'id'    => (string) $n,
			),
			range( 1, 251 )
		);
		$summary = DigestSummary::build(
			array(
				'files' => array(
					'at'   => 1000,
					'rows' => $rows,
				),
			),
			array(),
			null,
			1000
		);
		self::assertStringContainsString( 'partial', $summary['body'] );
		self::assertCount( 250, $summary['snapshot']['identities']['files'] );
	}
	public function test_vulnerability_risk_counts_appear_without_package_names(): void {
		$summary = DigestSummary::build(
			array(
				'vulnerabilities' => array(
					'at'   => 1000,
					'rows' => array(
						array(
							'state' => 'warn',
							'id'    => 'a',
							'risk'  => 'high',
						),
						array(
							'state' => 'pass',
							'id'    => 'b',
							'risk'  => 'watch',
						),
						array(
							'state' => 'pass',
							'id'    => 'c',
							'risk'  => 'low',
						),
					),
				),
			),
			array(),
			null,
			1000
		);
		self::assertStringContainsString( 'Package risk: 1 findings on high-risk packages; 1 packages to watch', $summary['body'] );
	}
}
