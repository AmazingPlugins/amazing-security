<?php

// Run on a disposable site: wp eval-file wp-content/plugins/amazing-security/tests/Integration/wordpress-login-rate.php.
use AmazingPlugins\Security\Integrity\WordPressOptions;
use AmazingPlugins\Security\Login\RateLimiter;
use AmazingPlugins\Security\Login\WordPressLoginSettings;
use AmazingPlugins\Security\Login\WordPressRateCounterStore;

global $wpdb;
$settings = new WordPressLoginSettings( new WordPressOptions() );
$store    = new WordPressRateCounterStore( $wpdb );
$limiter  = new RateLimiter( $settings, $store );
$key      = hash( 'sha256', 'disposable-login-rate-' . wp_generate_uuid4() );
$now      = time();
$before   = $settings->rateMode();

try {
	$settings->setRateMode( 'observe' );
	for ( $attempt = 0; $attempt < 5; ++$attempt ) {
		$limiter->afterFailure( $key, $now );
	}
	if ( $limiter->beforePassword( $key, $now + 1 )->blocked ) {
		throw new RuntimeException( 'Observe mode blocked a login.' );
	}
	$settings->setRateMode( 'block' );
	if ( ! $limiter->beforePassword( $key, $now + 1 )->blocked ) {
		throw new RuntimeException( 'Block mode did not deny a limited address.' );
	}
	if ( $limiter->beforePassword( $key, $now + 901 )->blocked ) {
		throw new RuntimeException( 'Block persisted past expiry.' );
	}
	$settings->setRateMode( 'off' );
	if ( $limiter->beforePassword( $key, $now + 1 )->blocked ) {
		throw new RuntimeException( 'Off mode blocked a login.' );
	}
	echo "Login rate integration passed.\n";
} finally {
	$settings->setRateMode( $before );
}
