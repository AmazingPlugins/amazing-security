<?php
if ( ! defined( 'WP_CLI' ) || ! WP_CLI || DB_HOST !== 'amsec-next-db' || ! in_array( DB_NAME, array( 'wordpress', 'wordpress69' ), true ) ) {
	exit( 1 );}
use AmazingPlugins\Security\Headers\{WordPressHeaderService, HeaderAction, HeaderPage, HeaderService, HttpHeaderClient, HeaderAssessment};
use AmazingPlugins\Security\Integrity\WordPressOptions;
$saved = array();
foreach ( array( 'amsec_headers_state', 'amsec_headers_lock' ) as $key ) {
	$saved[ $key ] = get_option( $key, null );
	delete_option( $key );
}$die      = static fn()=>static function ( $m, $t, $a ) {
throw new RuntimeException( 'denied:' . ( $a['response'] ?? 500 ) );
}$redirect = static function () {
	throw new RuntimeException( 'redirect' );
};
add_filter( 'wp_die_handler', $die );
add_filter( 'wp_redirect', $redirect );
wp_set_current_user( 1 );
$_SERVER['REQUEST_METHOD'] = 'POST';
try {
	$native = ( new WordPressHeaderService() )->create();
	$fp     = $native->fingerprint();
	$base   = array(
		'fingerprint' => $fp,
		'consent'     => '1',
		'_wpnonce'    => wp_create_nonce( 'amsec_headers_' . $fp ),
	);
	foreach ( array(
		'nonce'   => array( '_wpnonce' => 'bad' ),
		'target'  => array( 'fingerprint' => hash( 'sha256', 'another' ) ),
		'array'   => array( 'fingerprint' => array( $fp ) ),
		'consent' => array( 'consent' => '0' ),
	) as $name => $change ) {
		$_POST    = array_replace( $base, $change );
		$_REQUEST = $_POST;
		try {
			( new HeaderAction() )->handle();
			throw new LogicException( 'Header gate accepted ' . $name );
		} catch ( RuntimeException $e ) {
			if ( ! str_starts_with( $e->getMessage(), 'denied:' ) ) {
				throw $e;}
		}
	}
	foreach ( array( 'method', 'guest' ) as $name ) {
		$_POST    = $base;
		$_REQUEST = $_POST;
		if ( $name === 'method' ) {
			$_SERVER['REQUEST_METHOD'] = 'GET';
		} else {
			wp_set_current_user( 0 );
		}try {
			( new HeaderAction() )->handle();
			throw new LogicException( 'Header gate accepted ' . $name );
		} catch ( RuntimeException $e ) {
			if ( $e->getMessage() !== 'denied:403' ) {
				throw $e;
			}
		}$_SERVER['REQUEST_METHOD'] = 'POST';
		wp_set_current_user( 1 );}
	if ( get_option( 'amsec_headers_state', null ) !== null ) {
		throw new RuntimeException( 'Rejected request wrote state.' );}
	$_POST    = $base;
	$_REQUEST = $_POST;
	try {
		( new HeaderAction() )->handle();
		throw new LogicException( 'Native header action failed to redirect.' );
	} catch ( RuntimeException $e ) {
		if ( $e->getMessage() !== 'redirect' ) {
			throw $e;
		}
	}if ( $native->status()['latest']['result']['state'] !== 'unknown' ) {
		throw new RuntimeException( 'Private dummy homepage unexpectedly assessed.' );}
	delete_option( 'amsec_headers_state' );
	$calls     = 0;
	$unknown   = false;
	$transport = static function ( $url, $args ) use ( &$calls, &$unknown ) {
		++$calls;
		if ( $url !== 'https://example.org/blog/' || $args['redirection'] !== 0 || ! $args['sslverify'] || isset( $args['cookies'] ) ) {
			throw new RuntimeException( 'Unsafe adapter arguments.' );
		}if ( $unknown ) {
			return array(
				'response' => array( 'code' => 503 ),
				'headers'  => array(),
			);
		}return array(
			'response' => array( 'code' => 200 ),
			'headers'  => new WpOrg\Requests\Utility\CaseInsensitiveDictionary(
				array(
					'Content-Type'                        => 'text/html',
					'Strict-Transport-Security'           => 'max-age=100',
					'X-Content-Type-Options'              => 'nosniff',
					'X-Frame-Options'                     => 'DENY',
					'Content-Security-Policy-Report-Only' => "script-src 'nonce-PRIVATE'; report-uri https://secret.invalid/",
					'Set-Cookie'                          => 'PRIVATECOOKIE',
				)
			),
		);
	};
	$home      = 'https://example.org/blog/';
	$s         = new HeaderService( new WordPressOptions(), new HttpHeaderClient( $transport, static fn()=>array( '8.8.8.8' ) ), static fn()=>$home );
	$f         = hash( 'sha256', $home );
	$now       = time();
	if ( $s->check( $f, $now ) !== 'saved' || $s->check( $f, $now + 1 ) !== 'cached' || $calls !== 1 ) {
		throw new RuntimeException( 'Bounded adapter assessment/cooldown failed.' );
	}$good   = $s->status()['last_good'];
	$unknown = true;
	if ( $s->check( $f, $now + 600 ) !== 'saved' || $s->status()['last_good'] !== $good ) {
		throw new RuntimeException( 'Unknown result erased history.' );}
	$raw = get_option( 'amsec_headers_state' );
	foreach ( array( 'PRIVATE', 'secret.invalid', $home ) as $secret ) {
		if ( str_contains( $raw, $secret ) ) {
			throw new RuntimeException( 'Raw response or target stored.' );
		}
	}ob_start();
	( new HeaderPage( $s ) )->render();
	$html = ob_get_clean();
	foreach ( array( 'Server-side HEAD', 'Unknown or unsupported', 'Last assessed response', 'report-only', 'Header enforcement is unchanged' ) as $text ) {
		if ( ! str_contains( $html, $text ) ) {
			throw new RuntimeException( 'Header scope/report text missing: ' . $text );
		}
	}foreach ( array( 'PRIVATE', 'secret.invalid', $home ) as $secret ) {
		if ( str_contains( $html, $secret ) ) {
			throw new RuntimeException( 'Raw response rendered.' );}
	}
	if ( ( new HeaderAssessment() )->parse(
		200,
		array(
			'content-type'              => array( 'text/html' ),
			'strict-transport-security' => array( 'max-age=100; includesubdomains; includesubdomains' ),
		),
		true
	)['headers']['hsts'] !== 'review' ) {
		throw new RuntimeException( 'Duplicate HSTS directives accepted.' );}
	$bad = json_decode( $raw, true );
	$bad['last_good']['result']['headers']['csp'] = 'safe';
	update_option( 'amsec_headers_state', wp_json_encode( $bad ), false );
	if ( $s->status() !== array( 'invalid' => true ) ) {
		throw new RuntimeException( 'Corrupt result accepted.' );
	}update_option( 'amsec_headers_state', $raw, false );
	$id = wp_create_user( 'amsec-header-sub-' . bin2hex( random_bytes( 4 ) ), bin2hex( random_bytes( 16 ) ) );
	if ( is_wp_error( $id ) ) {
		throw new RuntimeException( 'Subscriber fixture failed.' );
	}( new WP_User( $id ) )->set_role( 'subscriber' );
	wp_set_current_user( $id );
	try {
		foreach ( array( 'action', 'page' ) as $which ) {
			try {
				if ( $which === 'action' ) {
					( new HeaderAction() )->handle();
				} else {
					( new HeaderPage() )->render();
				}throw new LogicException( 'Subscriber allowed.' );
			} catch ( RuntimeException $e ) {
				if ( $e->getMessage() !== 'denied:403' ) {
					throw $e;
				}
			}
		}
	} finally {
		wp_set_current_user( 1 );
		require_once ABSPATH . 'wp-admin/includes/user.php';
		wp_delete_user( $id );}
	echo 'Private-home refusal, HTTP API adapter controlled response, nonce/consent/POST/role gates, cooldown, normalized redacted report, unknown history and corrupt state passed.' . PHP_EOL;
} finally {
	remove_filter( 'wp_die_handler', $die );
	remove_filter( 'wp_redirect', $redirect );
	wp_set_current_user( 1 );
	foreach ( $saved as $key => $value ) {
		if ( $value === null ) {
			delete_option( $key );
		} else {
			update_option( $key, $value, false );}
	}
}
