<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit;

use AmazingPlugins\Security\Checks\AdminAccountsCheck;
use AmazingPlugins\Security\Checks\DebugDisplayCheck;
use AmazingPlugins\Security\Checks\FileEditorCheck;
use AmazingPlugins\Security\Checks\HttpsAdminCheck;
use AmazingPlugins\Security\Checks\UpdatePostureCheck;
use AmazingPlugins\Security\Checks\Values;
use AmazingPlugins\Security\Scan\ScanContext;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class ChecksTest extends TestCase {
    public static function cases(): array {
        return [
            'update' => [UpdatePostureCheck::class, 'coreUpdateAvailable'],
            'debug' => [DebugDisplayCheck::class, 'debugDisplayed'],
            'file editor' => [FileEditorCheck::class, 'fileEditorDisabled'],
            'HTTPS' => [HttpsAdminCheck::class, 'adminUsesHttps'],
            'admin login' => [AdminAccountsCheck::class, 'hasDefaultAdminLogin'],
        ];
    }

    #[DataProvider('cases')]
    public function test_unreadable_value_is_unknown(string $checkClass, string $method): void {
        $values = $this->createMock(Values::class);
        $values->method($method)->willReturn(null);
        $result = (new $checkClass($values))->run(new ScanContext())[0];
        self::assertSame('unknown', $result->state);
        self::assertSame('unavailable', $result->coverage);
    }

    #[DataProvider('cases')]
    public function test_observed_value_has_a_source_and_time(string $checkClass, string $method): void {
        $values = $this->createMock(Values::class);
        $values->method($method)->willReturn(true);
        $result = (new $checkClass($values))->run(new ScanContext())[0];
        self::assertContains($result->state, ['pass', 'warn']);
        self::assertStringStartsWith('https://developer.wordpress.org/', $result->sourceUrl);
        self::assertSame('complete', $result->coverage);
    }

    #[DataProvider('cases')]
    public function test_opposite_observed_value_still_has_complete_coverage(string $checkClass, string $method): void {
        $values = $this->createMock(Values::class);
        $values->method($method)->willReturn(false);
        $result = (new $checkClass($values))->run(new ScanContext())[0];
        self::assertContains($result->state, ['pass', 'warn']);
        self::assertSame('complete', $result->coverage);
    }
}
