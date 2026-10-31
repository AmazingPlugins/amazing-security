<?php
// Synthetic display fixtures on a disposable WordPress site; no plugin files are changed.
use AmazingPlugins\Security\Findings\CheckResult;
use AmazingPlugins\Security\Vulnerabilities\VulnerabilityReport;
use AmazingPlugins\Security\Vulnerabilities\WordPressVulnerabilityReportStore;
use AmazingPlugins\Security\Integrity\WordPressOptions;
use AmazingPlugins\Security\Integrity\WordPressIntegrityStore;
use AmazingPlugins\Security\Integrity\IntegrityCursor;
use AmazingPlugins\Security\Integrity\IntegrityStep;

require_once ABSPATH . 'wp-admin/includes/plugin.php';
$options = new WordPressOptions();
$report  = new VulnerabilityReport(
	array(
		new CheckResult(
			'vulnerability',
			'warn',
			'Synthetic UI finding: <script>unsafe text must remain plain text</script>',
			'https://www.wpvulnerability.com/',
			new DateTimeImmutable( '-2 days' ),
			'high',
			'complete',
			array(
				'severity'     => 'critical',
				'cvss_score'   => 9.8,
				'cvss_version' => '3.1',
				'type'         => 'plugin',
				'slug'         => str_repeat( 'long-package-name-', 8 ),
				'version'      => '1.0',
			),
			'ui-fixture-critical'
		),
		new CheckResult(
			'vulnerability',
			'unknown',
			'Provider unavailable for this package.',
			'https://www.wpvulnerability.com/',
			new DateTimeImmutable(),
			'low',
			'unavailable',
			array(
				'type'    => 'theme',
				'slug'    => 'custom-theme',
				'version' => '1.0',
			)
		),
	),
	true,
	'Synthetic display fixture: partial coverage',
	gmdate( 'c', time() - 172800 )
);
( new WordPressVulnerabilityReportStore( $options ) )->save( $report, false );
$path               = WP_PLUGIN_DIR . '/akismet/akismet.php';
$version            = get_plugin_data( $path, false, false )['Version'];
$cursor             = new IntegrityCursor( wp_generate_uuid4() );
$cursor->findings[] = new CheckResult(
	'integrity-file',
	'warn',
	'Synthetic repair preview fixture.',
	'https://downloads.wordpress.org/plugin-checksums/akismet/' . $version . '.json',
	new DateTimeImmutable(),
	'high',
	'complete',
	array(
		'package_type'    => 'plugin',
		'package'         => 'akismet:' . $version,
		'path'            => 'akismet.php',
		'reason'          => 'ok',
		'observed_sha256' => hash_file( 'sha256', $path ),
	),
	str_repeat( 'd', 32 )
);
delete_option( 'amsec_security_scanner_integrity_active' );
$store = new WordPressIntegrityStore( $options );
$store->begin( $cursor->scanId, $cursor );
$store->saveProgress( $cursor->scanId, new IntegrityStep( $cursor, true ) );
echo 'Synthetic dashboard and repair review fixtures ready.';
