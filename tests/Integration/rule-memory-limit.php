<?php
// Standalone regression: run with php -d memory_limit=64M against a plugin path.
spl_autoload_register(
	static function ( string $class ) {
		$prefix = 'AmazingPlugins\\Security\\';
		if ( str_starts_with( $class, $prefix ) ) {
			require $GLOBALS['argv'][1] . '/src/' . str_replace( '\\', '/', substr( $class, strlen( $prefix ) ) ) . '.php';
		} }
);
$matcher = new AmazingPlugins\Security\FileScan\RuleMatcher( new AmazingPlugins\Security\FileScan\BundledRulePack() );
try {
	$matcher->match( '<?php ' . str_repeat( '$a;', 600000 ), 'dense.php' );
	throw new LogicException( 'Dense source was not reported unavailable.' );
} catch ( RuntimeException $error ) {
	if ( ! in_array( $error->getMessage(), array( 'rule_limit', 'rule_memory_limit' ), true ) ) {
		throw $error; }
}
if ( count( $matcher->match( '<?php eval($_POST["fixture"]);', 'small.php' ) ) !== 1 ) {
	throw new RuntimeException( 'Small file could not be scanned after bounded refusal.' ); }
echo 'Dense input refused without exhausting 64 MiB; following small file scanned.' . PHP_EOL;
