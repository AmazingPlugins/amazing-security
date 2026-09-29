<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Tests\Unit\FileScan;
use AmazingPlugins\Security\FileScan\BundledRulePack;
use AmazingPlugins\Security\FileScan\RuleMatcher;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class RuleCorpusTest extends TestCase {
    public static function corpus(): array {
        $data = json_decode( file_get_contents( dirname( __DIR__, 2 ) . '/Fixtures/FileScan/corpus.json' ), true, flags: JSON_THROW_ON_ERROR );
        $cases = array();
        foreach ( $data['cases'] as $case ) { $cases[ $case['kind'] . ':' . $case['name'] ] = array( $case['code'], $case['expected'] ); }
        return $cases;
    }
    #[DataProvider('corpus')]
    public function test_rule_corpus( string $code, array $expected ): void {
        $hits = ( new RuleMatcher( new BundledRulePack() ) )->match( $code, 'fixture.php' );
        self::assertSame( $expected, array_column( $hits, 'ruleId' ) );
        foreach ( $hits as $hit ) { self::assertGreaterThan( 0, $hit->line ); self::assertStringNotContainsString( 'example.invalid', json_encode( $hit ) ); }
    }
}
