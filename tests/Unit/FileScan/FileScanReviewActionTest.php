<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\FileScan;

use AmazingPlugins\Security\Admin\FileScanReviewAction;
use AmazingPlugins\Security\FileScan\FileScanCursor;
use AmazingPlugins\Security\FileScan\FileScanStep;
use PHPUnit\Framework\TestCase;

final class FileScanReviewActionTest extends TestCase {
	public function test_note_requires_capability_nonce_and_current_finding(): void {
		self::assertFalse( FileScanReviewAction::canNote( false, true, true ) );
		self::assertFalse( FileScanReviewAction::canNote( true, false, true ) );
		self::assertFalse( FileScanReviewAction::canNote( true, true, false ) );
		self::assertTrue( FileScanReviewAction::canNote( true, true, true ) );
	}

	public function test_note_has_bounded_text_and_stable_id(): void {
		self::assertFalse( FileScanReviewAction::validInput( 'changed', 'reviewed' ) );
		self::assertFalse( FileScanReviewAction::validInput( str_repeat( 'a', 32 ), str_repeat( 'x', 501 ) ) );
		self::assertTrue( FileScanReviewAction::validInput( str_repeat( 'a', 32 ), 'Reviewed with developer.' ) );
	}

	public function test_partial_finished_report_still_allows_note_on_its_finding(): void {
		$id                 = str_repeat( 'a', 32 );
		$cursor             = new FileScanCursor( 'scan-1' );
		$cursor->partial    = true;
		$cursor->finished   = true;
		$cursor->findings[] = array( 'id' => $id );
		self::assertTrue( FileScanReviewAction::hasCurrentFinding( new FileScanStep( $cursor, true ), null, $id ) );
		self::assertFalse( FileScanReviewAction::hasCurrentFinding( new FileScanStep( $cursor, true ), null, str_repeat( 'b', 32 ) ) );
	}
}
