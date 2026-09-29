<?php
// Disposable Docker site only, via wp eval-file. Makes bounded HTTP requests to this same site.
// Usage: AMSEC_BENCHMARK_URL=http://container wp eval-file ... --user=admin
if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) { exit( 1 ); }
use AmazingPlugins\Security\Firewall\RequestInspector;

global $wpdb;
$base = getenv( 'AMSEC_BENCHMARK_URL' );
if ( ! is_string( $base ) || ! preg_match( '~^http://amsec-next-wp(?:69)?$~D', $base ) ) { throw new RuntimeException( 'Only the named disposable Docker sites are allowed.' ); }
if ( 'amsec-next-db' !== DB_HOST || DB_NAME !== ( str_ends_with( $base, '69' ) ? 'wordpress69' : 'wordpress' ) ) { throw new RuntimeException( 'Bootstrap database does not match the disposable HTTP target.' ); }
if ( str_ends_with( $base, '69' ) && ! class_exists( 'WC_Product_Simple' ) ) { throw new RuntimeException( 'WooCommerce is required for the 6.9 cart matrix.' ); }
$toggle = WPMU_PLUGIN_DIR . '/amsec-request-benchmark.php';
if ( file_exists( $toggle ) ) { throw new RuntimeException( 'Benchmark toggle already exists; inspect it before proceeding.' ); }
$read = static function () use ( $wpdb ) { return $wpdb->get_var( $wpdb->prepare( "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s", 'amsec_rest_observations' ) ); };
$saved = $read();
$clear = static function () use ( $wpdb ): void { $wpdb->delete( $wpdb->options, array( 'option_name' => 'amsec_rest_observations' ) ); wp_cache_delete( 'amsec_rest_observations', 'options' ); wp_cache_delete( 'notoptions', 'options' ); wp_cache_delete( 'alloptions', 'options' ); };
$summary = static function () use ( $read ): array { return json_decode( $read() ?? '{}', true ) ?? array(); };
$count = static function () use ( $summary ): int { return array_sum( array_column( $summary(), 'count' ) ); };
$assert = static function ( bool $pass, string $message ): void { if ( ! $pass ) { throw new RuntimeException( $message ); } };
$request = static function ( string $path, ?array $body = null, ?string $token = null ) use ( $base ): array {
    $headers = array();
    $ch = curl_init( $base . $path );
    curl_setopt_array( $ch, array( CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 20, CURLOPT_HEADERFUNCTION => static function ( $ch, $line ) use ( &$headers ) { $pair = explode( ':', $line, 2 ); if ( 2 === count( $pair ) ) { $headers[strtolower( trim( $pair[0] ) )] = trim( $pair[1] ); } return strlen( $line ); } ) );
    $sendHeaders = array();
    if ( null !== $token ) { $sendHeaders[] = 'Cart-Token: ' . $token; }
    if ( null !== $body ) { $sendHeaders[] = 'Content-Type: application/json'; curl_setopt( $ch, CURLOPT_POSTFIELDS, json_encode( $body ) ); }
    curl_setopt( $ch, CURLOPT_HTTPHEADER, $sendHeaders );
    $raw = curl_exec( $ch );
    $status = curl_getinfo( $ch, CURLINFO_RESPONSE_CODE );
    if ( false === $raw ) { throw new RuntimeException( 'Local HTTP request failed: ' . curl_errno( $ch ) ); }
    return array( 'status' => $status, 'headers' => $headers, 'body' => json_decode( $raw, true ) );
};
$product = null;
try {
    $clear();
    $cases = array(
        'plain traversal' => array( 'probe=..%2Fdocs', 1 ),
        'double encoded traversal' => array( 'probe=%252e%252e%252fdocs', 1 ),
        'triple encoded traversal' => array( 'probe=%25252e%25252e%25252fdocs', 0 ),
        'union all' => array( 'probe=UNION%20ALL%20SELECT', 1 ),
        'SQL comments evade narrow rule' => array( 'probe=UNION%2F%2Ax%2A%2FSELECT', 0 ),
        'nested values outside coverage' => array( 'probe%5Bnested%5D=..%2Fdocs', 0 ),
        'credential value excluded' => array( 'token=..%2Fprivate', 0 ),
        'oversized value outside coverage' => array( 'probe=' . str_repeat( 'a', 2049 ) . '..%2Fdocs', 0 ),
        'too many fields outside coverage' => array( http_build_query( array_fill_keys( range( 1, 51 ), '../docs' ) ), 0 ),
    );
    $results = array();
    foreach ( $cases as $label => [ $query, $expected ] ) {
        $before = $count();
        $response = $request( '/wp-json/wp/v2/posts?' . $query );
        $delta = $count() - $before;
        $assert( 200 === $response['status'] && $expected === $delta, 'REST coverage expectation failed: ' . $label );
        $results[$label] = array( 'http' => $response['status'], 'observations' => $delta );
    }
    $inspector = new RequestInspector();
    foreach ( array( array( 'x' => array( '../' ) ), array( 'x' => str_repeat( 'a', 2049 ) ), array_fill( 0, 51, '../' ), array( 'a' => str_repeat( 'a', 2048 ), 'b' => str_repeat( 'a', 2048 ), 'c' => str_repeat( 'a', 2048 ), 'd' => str_repeat( 'a', 2048 ), 'e' => '../' ) ) as $query ) {
        $assert( 'partial' === $inspector->inspect( $query, false )['state'], 'A bounded input was labeled complete.' );
    }
    $assert( 'skip' === $inspector->inspect( array( 'probe' => '../' ), true )['state'], 'Authenticated exemption failed.' );
    $before = $count();
    $response = $request( '/wp-json/wp/v2/posts', array( 'probe' => '../private UNION SELECT' ) );
    $assert( 401 === $response['status'] && $before === $count(), 'Anonymous body request or exclusion changed.' );
    $results['JSON body excluded; WordPress denies create'] = array( 'http' => $response['status'], 'observations' => 0 );

    if ( class_exists( 'WC_Product_Simple' ) ) {
        $product = new WC_Product_Simple();
        $product->set_name( 'Disposable Amazing Security cart fixture' );
        $product->set_regular_price( '1' );
        $product->set_virtual( true );
        $product->set_status( 'publish' );
        $id = $product->save();
        $cart = $request( '/wp-json/wc/store/v1/cart' );
        $token = $cart['headers']['cart-token'] ?? null;
        $assert( 200 === $cart['status'] && is_string( $token ), 'Cart session could not start.' );
        $add = $request( '/wp-json/wc/store/v1/cart/add-item', array( 'id' => $id, 'quantity' => 1 ), $token );
        $assert( in_array( $add['status'], array( 200, 201 ), true ) && 1 === ( $add['body']['items_count'] ?? null ), 'Guest cart add failed: HTTP ' . $add['status'] . ', code ' . ( $add['body']['code'] ?? 'none' ) . ', count ' . ( $add['body']['items_count'] ?? 'none' ) );
        $key = $add['body']['items'][0]['key'];
        $update = $request( '/wp-json/wc/store/v1/cart/update-item', array( 'key' => $key, 'quantity' => 2 ), $token );
        $assert( 200 === $update['status'] && 2 === ( $update['body']['items_count'] ?? null ), 'Guest cart update failed.' );
        $remove = $request( '/wp-json/wc/store/v1/cart/remove-item', array( 'key' => $key ), $token );
        $assert( 200 === $remove['status'] && 0 === ( $remove['body']['items_count'] ?? null ), 'Guest cart removal failed.' );
        $results['WooCommerce guest cart'] = 'read/add/update/remove passed; token kept in memory; no checkout';
    }

    if ( ! class_exists( 'WC_Product_Simple' ) ) { $results['WooCommerce guest cart'] = 'SKIPPED: WooCommerce is not installed on this minimum-version site'; }
    $batches = array();
    foreach ( array( 'ordinary' => 'hello', 'matching' => '../docs UNION SELECT' ) as $kind => $query ) {
        foreach ( array( 'disabled', 'observe', 'observe', 'disabled' ) as $mode ) {
            if ( 'disabled' === $mode ) {
                $assert( false !== file_put_contents( $toggle, '<?php define("AMSEC_DISABLE_FIREWALL", true);' ), 'Could not install emergency-disable toggle.' );
            } elseif ( file_exists( $toggle ) ) { unlink( $toggle ); }
            $clear();
            // Warm the runtime before timing; observation counts are reset afterward.
            $request( '/wp-json/wp/v2/posts?probe=' . rawurlencode( $query ) );
            $clear();
            $times = array();
            $statuses = array();
            $started = microtime( true );
            for ( $batch = 0; $batch < 10; ++$batch ) {
                $multi = curl_multi_init();
                $handles = array();
                try {
                    for ( $i = 0; $i < 4; ++$i ) {
                        $ch = curl_init( $base . '/wp-json/wp/v2/posts?probe=' . rawurlencode( $query ) );
                        curl_setopt_array( $ch, array( CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 20 ) );
                        curl_multi_add_handle( $multi, $ch );
                        $handles[] = $ch;
                    }
                    do { $code = curl_multi_exec( $multi, $running ); if ( $running ) { curl_multi_select( $multi, 0.5 ); } } while ( $running && CURLM_OK === $code );
                    foreach ( $handles as $ch ) {
                        $assert( 0 === curl_errno( $ch ), 'Load request transport failed.' );
                        $statuses[] = curl_getinfo( $ch, CURLINFO_RESPONSE_CODE );
                        $times[] = curl_getinfo( $ch, CURLINFO_TOTAL_TIME ) * 1000;
                    }
                } finally { foreach ( $handles as $ch ) { curl_multi_remove_handle( $multi, $ch ); } curl_multi_close( $multi ); }
            }
            $elapsed = microtime( true ) - $started;
            sort( $times );
            $assert( array( 200 ) === array_values( array_unique( $statuses ) ), 'Non-200 response under load.' );
            $observations = $count();
            $assert( ( 'disabled' === $mode || 'ordinary' === $kind ) ? 0 === $observations : $observations > 0 && $observations <= 80, 'Emergency toggle or observation count failed.' );
            $stored = $read() ?? '';
            $assert( strlen( $stored ) < 512 && ! str_contains( $stored, 'docs' ) && ! str_contains( $stored, 'UNION' ), 'Observation storage leaked request content or exceeded bound.' );
            $batches[] = array( 'query' => $kind, 'mode' => $mode, 'requests' => 40, 'concurrency' => 4, 'p50_ms' => round( $times[19], 2 ), 'p95_ms' => round( $times[37], 2 ), 'requests_per_second' => round( 40 / $elapsed, 2 ), 'observation_count' => $observations, 'expected_observations' => ( 'observe' === $mode && 'matching' === $kind ? 80 : 0 ), 'unrecorded_observations' => ( 'observe' === $mode && 'matching' === $kind ? 80 - $observations : 0 ), 'stored_bytes' => strlen( $stored ) );
        }
    }
    $report = json_encode( array( 'wordpress' => get_bloginfo( 'version' ), 'php_cli' => PHP_VERSION, 'woocommerce' => defined( 'WC_VERSION' ) ? WC_VERSION : null, 'coverage' => $results, 'batches' => $batches ), JSON_PRETTY_PRINT ) . PHP_EOL;
} finally {
    $cleanupErrors = array();
    if ( file_exists( $toggle ) && ! unlink( $toggle ) ) { $cleanupErrors[] = 'disable toggle'; }
    if ( null !== $product ) { $fixtureId = $product->get_id(); $product->delete( true ); if ( $fixtureId && null !== get_post( $fixtureId ) ) { $cleanupErrors[] = 'product'; } }
    $clear();
    if ( null !== $saved && ! add_option( 'amsec_rest_observations', $saved, '', false ) ) { $cleanupErrors[] = 'observation restoration'; }
    if ( $read() !== $saved ) { $cleanupErrors[] = 'stored observation value'; }
    if ( array() !== $cleanupErrors ) { throw new RuntimeException( 'Cleanup failed: ' . implode( ', ', $cleanupErrors ) ); }
}
echo $report;
