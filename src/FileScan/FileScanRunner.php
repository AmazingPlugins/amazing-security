<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\FileScan;

use AmazingPlugins\Security\Integrity\IntegrityBudget;
use AmazingPlugins\Security\Scan\ScanContext;
use DateTimeImmutable;
use RuntimeException;

final class FileScanRunner {
	public function __construct( private readonly SafeFileWalker $walker = new SafeFileWalker(), private readonly BoundedContentReader $reader = new BoundedContentReader(), private readonly ContentCandidateSelector $selector = new ContentCandidateSelector(), private readonly RuleMatcher $matcher = new RuleMatcher( new BundledRulePack() ) ) {}

	/** @param FileScanTarget[] $targets */
	public function step( array $targets, FileScanCursor $cursor, ScanContext $context ): FileScanStep {
		$this->walker->beginStep();
		$started   = microtime( true );
		$stepLimit = min( 250, $context->entryLimit );
		$budget    = new IntegrityBudget( $stepLimit, min( 33554432, max( 0, 134217728 - $cursor->bytes ) ), min( 5.0, max( 0.0, 30.0 - $cursor->elapsed ) ), max( 0.0, $context->deadline - $started ) );
		$count     = 0;
		while ( $count < $stepLimit && $budget->hasTime() && ! $cursor->finished ) {
			$before = clone $cursor;
			$item   = $this->walker->next( $targets, $cursor );
			if ( null === $item ) {
				break;
			}
			$target   = $targets[ $item['target_index'] ];
			$relative = $item['path'];
			$size     = $item['size'];
			if ( $this->mayScanContent( $target, $relative, $item['extra'] ) && $size <= 2097152 && $size > $budget->remainingBytes() ) {
				if ( $cursor->bytes + $size > 134217728 ) {
					$cursor->partial  = true;
					$cursor->finished = true;
				} else {
					$cursor = $before;
				}
				break;
			}
			++$count;
			if ( $item['extra'] ) {
				$this->finding( $cursor, $target, $relative, 'warn', 'extra', '', 0, 'Review file not in the published release.', '' );
			}
			if ( ! $this->mayScanContent( $target, $relative, $item['extra'] ) ) {
				continue;
			}
			$result = $this->reader->read( $target->root, $relative, $budget );
			if ( 'ok' !== $result->state ) {
				++$cursor->unknown;
				$cursor->partial = true;
				$this->finding( $cursor, $target, $relative, 'inconclusive', 'unscanned', '', 0, 'File could not be scanned.', $result->state );
				continue;
			}
			if ( ! $this->selector->eligible( $target, $relative, $result->sha256, $item['extra'] ) ) {
				++$cursor->verified;
				continue;
			}
			try {
				$hits = $this->matcher->match( $result->bytes, $relative );
			} catch ( RuntimeException $error ) {
				++$cursor->unknown;
				$cursor->partial = true;
				$this->finding( $cursor, $target, $relative, 'inconclusive', 'unscanned', '', 0, 'Code rule check could not finish.', $error->getMessage() );
				continue;
			}
			++$cursor->scanned;
			foreach ( $hits as $hit ) {
				$this->finding( $cursor, $target, $relative, 'warn', 'suspected', $hit->ruleId, $hit->line, $hit->summary, '' );
			}
		}
		$cursor->bytes   += $budget->bytes();
		$cursor->elapsed += microtime( true ) - $started;
		if ( ! $cursor->finished && ( $cursor->processed >= 5000 || $cursor->bytes >= 134217728 || $cursor->elapsed >= 30 ) ) {
			$cursor->partial  = true;
			$cursor->finished = true;
		}
		return new FileScanStep( $cursor, $cursor->finished );
	}

	private function mayScanContent( FileScanTarget $target, string $relative, bool $extra ): bool {
		if ( ! preg_match( '/\.(?:php|phtml|php[0-9]+)$/iD', $relative ) ) {
			return false;
		}
		return 'core' !== $target->kind || ( $extra && ( str_starts_with( $relative, 'wp-admin/' ) || str_starts_with( $relative, 'wp-includes/' ) ) );
	}

	private function finding( FileScanCursor $cursor, FileScanTarget $target, string $relative, string $state, string $kind, string $ruleId, int $line, string $summary, string $reason ): void {
		if ( count( $cursor->findings ) >= 250 ) {
			++$cursor->omitted;
			$cursor->partial = true;
			return;
		}
		$cursor->findings[] = array(
			'id'        => substr( hash( 'sha256', $target->kind . ':' . $target->identity . ':' . $relative . ':' . $kind . ':' . $ruleId ), 0, 32 ),
			'state'     => $state,
			'kind'      => $kind,
			'package'   => $target->identity,
			'path'      => $relative,
			'rule_id'   => $ruleId,
			'version'   => ( new BundledRulePack() )->version(),
			'line'      => $line,
			'reason'    => $reason,
			'summary'   => $summary,
			'tested_at' => ( new DateTimeImmutable() )->format( 'c' ),
		);
	}
}
