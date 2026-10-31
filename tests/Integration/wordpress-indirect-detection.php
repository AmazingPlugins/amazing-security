<?php
// Samples are JSON strings, read as data. No sample is included or executed.
if ( ! defined( 'WP_CLI' ) || ! WP_CLI || DB_HOST !== 'amsec-next-db' || ! in_array( DB_NAME, array( 'wordpress', 'wordpress69' ), true ) ) {
	exit( 1 );}
use AmazingPlugins\Security\FileScan\RuleMatcher;
use AmazingPlugins\Security\FileScan\BundledRulePack;
$path  = '/tmp/amsec-rule-fixtures.json';
$bytes = file_get_contents( $path );
if ( ! is_string( $bytes ) || strlen( $bytes ) > 262144 ) {
	throw new RuntimeException( 'Bounded fixture read failed.' );
}$cases = json_decode( $bytes, true, flags:JSON_THROW_ON_ERROR )['cases'];
if ( count( $cases ) > 250 ) {
	throw new RuntimeException( 'Fixture budget exceeded.' );
}$matcher = new RuleMatcher( new BundledRulePack() );
$counts   = array(
	'suspected' => 0,
	'benign'    => 0,
	'known-gap' => 0,
);
foreach ( $cases as $case ) {
	$hits = $matcher->match( $case['code'], 'inert-fixture.txt' );
	if ( array_column( $hits, 'ruleId' ) !== $case['expected'] ) {
		throw new RuntimeException( 'Installed rule regression: ' . $case['name'] );
	}++$counts[ $case['kind'] ];
}echo json_encode(
	array(
		'rule_pack'        => ( new BundledRulePack() )->version(),
		'cases'            => count( $cases ),
		'categories'       => $counts,
		'all_expected'     => true,
		'samples_executed' => false,
	),
	JSON_PRETTY_PRINT
) . PHP_EOL;
