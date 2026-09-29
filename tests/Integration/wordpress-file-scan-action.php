<?php

// Run with AMSEC_CASE=editor|forged|start|inspect|resume and wp-load.php on a disposable site.
use AmazingPlugins\Security\Admin\AdminPage;
use AmazingPlugins\Security\Admin\FileScanAction;
use AmazingPlugins\Security\FileScan\WordPressFileScanStore;
use AmazingPlugins\Security\Integrity\WordPressOptions;

$case = getenv( 'AMSEC_CASE' );
if ( 'editor' === $case ) {
	$editor = get_user_by( 'login', 'amsec_file_fixture_editor' );
	if ( ! $editor ) {
		$id = wp_insert_user( array( 'user_login' => 'amsec_file_fixture_editor', 'user_pass' => wp_generate_password( 32 ), 'user_email' => 'amsec-file-editor@example.invalid', 'role' => 'editor' ) );
		if ( is_wp_error( $id ) ) {
			throw new RuntimeException( 'Could not make editor fixture.' );
		}
		$editor = get_user_by( 'id', $id );
	}
	wp_set_current_user( $editor->ID );
} else {
	wp_set_current_user( 1 );
}

add_filter( 'pre_http_request', static fn() => new WP_Error( 'amsec_fixture_offline', 'Fixture keeps outbound requests offline.' ) );

if ( 'plan' === $case ) {
	require_once ABSPATH . 'wp-admin/includes/plugin.php';
	$fixtureDirectory = WP_PLUGIN_DIR . '/amsec_fixture_plugin';
	if ( ! is_dir( $fixtureDirectory ) ) {
		mkdir( $fixtureDirectory );
	}
	file_put_contents( $fixtureDirectory . '/main.php', '<?php /* Plugin Name: Amazing Security scan fixture */' );
	wp_clean_plugins_cache();
	$method = new ReflectionMethod( FileScanAction::class, 'plugins' );
	$plugins = $method->invoke( new FileScanAction() );
	unlink( $fixtureDirectory . '/main.php' );
	rmdir( $fixtureDirectory );
	wp_clean_plugins_cache();
	$slugs = array_column( $plugins, 'slug' );
	if ( ! in_array( 'amazing-security', $slugs, true ) || ! in_array( 'hello.php', array_column( $plugins, 'single_file' ), true ) || ! in_array( 'amsec_fixture_plugin', $slugs, true ) ) {
		throw new RuntimeException( 'The file scan omitted its own package or a local plugin.' );
	}
	$folder = $plugins[ array_search( 'amsec_fixture_plugin', $slugs, true ) ];
	if ( WP_PLUGIN_DIR . '/amsec_fixture_plugin' !== $folder['root'] || ! $folder['local_only'] ) {
		throw new RuntimeException( 'The nonrepository plugin lacked a bounded local root.' );
	}
	$candidates = ( new ReflectionMethod( FileScanAction::class, 'manifestPlugins' ) )->invoke( new FileScanAction(), $plugins );
	if ( in_array( 'amazing-security', array_column( $candidates, 'slug' ), true ) || in_array( 'hello.php', array_column( $candidates, 'slug' ), true ) || in_array( 'amsec_fixture_plugin', array_column( $candidates, 'slug' ), true ) ) {
		throw new RuntimeException( 'Local-only plugins consumed repository manifest slots.' );
	}
	echo 'File action: own and single-file plugins are in the local scan plan.' . PHP_EOL;
	return;
}

if ( 'inspect' === $case ) {
	require_once ABSPATH . 'wp-admin/includes/template.php';
	$progress = ( new WordPressFileScanStore( new WordPressOptions() ) )->latestProgress();
	if ( null === $progress || $progress->finished || $progress->cursor->processed > 250 ) {
		throw new RuntimeException( 'Expected a bounded, resumable file scan.' );
	}
	ob_start();
	( new AdminPage() )->render();
	$html = ob_get_clean();
	if ( ! str_contains( $html, 'Continue file scan' ) || ! str_contains( $html, 'Scan in progress' ) || str_contains( $html, 'malware-free' ) ) {
		throw new RuntimeException( 'Admin page omitted continuation or showed an all-clear.' );
	}
	echo 'File action: bounded start and continue control passed.' . PHP_EOL;
	return;
}

if ( 'start' === $case ) {
	$uploads = wp_upload_dir();
	if ( ! is_dir( $uploads['basedir'] ) ) {
		mkdir( $uploads['basedir'], 0775, true );
	}
	for ( $i = 0; $i < 251; ++$i ) {
		file_put_contents( $uploads['basedir'] . '/amsec-fixture-' . sprintf( '%03d', $i ) . '.php', '<?php echo 1;' );
	}
}

if ( 'resume' === $case ) {
	$progress = ( new WordPressFileScanStore( new WordPressOptions() ) )->latestProgress();
	if ( null === $progress || $progress->finished ) {
		throw new RuntimeException( 'No resumable file scan.' );
	}
	$_POST['scan_id'] = $progress->cursor->scanId;
	$_POST['_wpnonce'] = wp_create_nonce( 'amazing_security_file_scan_resume' );
	$_REQUEST['_wpnonce'] = $_POST['_wpnonce'];
	( new FileScanAction() )->resume();
}

$_POST['_wpnonce'] = 'forged' === $case ? 'invalid' : wp_create_nonce( 'amazing_security_file_scan_start' );
$_REQUEST['_wpnonce'] = $_POST['_wpnonce'];
( new FileScanAction() )->start();
