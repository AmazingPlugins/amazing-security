<?php

// Run with wp eval-file on a disposable WordPress site with the private ZIP active.
use AmazingPlugins\Security\Admin\FileScanAction;
use AmazingPlugins\Security\Admin\IntegrityScanAction;
use AmazingPlugins\Security\FileScan\WordPressFileScanStore;
use AmazingPlugins\Security\Integrity\WordPressIntegrityStore;
use AmazingPlugins\Security\Integrity\WordPressOptions;
use AmazingPlugins\Security\Schedule\SuiteCycle;

$options = new WordPressOptions();
$integrity = new WordPressIntegrityStore( $options );
$files = new WordPressFileScanStore( $options );
$cycle = new SuiteCycle( $options );
$options->delete( 'amsec_suite_cycle' );
if ( ! $cycle->start( time() ) ) {
	throw new RuntimeException( 'Could not start scheduled suite.' );
}

( new IntegrityScanAction() )->scheduled();
if ( null === $integrity->latestProgress() && null === $integrity->latestCompleted() ) {
	throw new RuntimeException( 'Scheduled integrity step saved no state.' );
}

$options->delete( 'amsec_suite_cycle' );
if ( ! $cycle->start( time() ) || ! $cycle->advance( 'integrity', 'files', time() ) ) {
	throw new RuntimeException( 'Could not move test to file stage.' );
}
( new FileScanAction() )->scheduled();
if ( null === $files->latestProgress() && null === $files->latestCompleted() ) {
	throw new RuntimeException( 'Scheduled file step saved no state.' );
}

echo 'Scheduled integrity and file steps saved state.';
