<?php
if(!defined('WP_CLI')||!WP_CLI||DB_HOST!=='amsec-next-db'||!in_array(DB_NAME,['wordpress','wordpress69'],true)){exit(1);}
use AmazingPlugins\Security\Activity\ActivityRepository;
use AmazingPlugins\Security\Integrity\WordPressOptions;
use AmazingPlugins\Security\Mcp\McpPreferences;
use AmazingPlugins\Security\Login\WordPressLoginSettings;
use AmazingPlugins\Security\Vulnerabilities\VulnerabilityPreferences;
global $wpdb;wp_set_current_user(1);update_option('amsec_activity_enabled','1',false);
$keys=['amsec_security_scanner_mcp_enabled','amsec_security_scanner_vulnerability_direct_enabled','amsec_login_rate_mode','amsec_alerts_enabled'];
foreach($keys as $key){delete_option($key);}
$options=new WordPressOptions();
(new McpPreferences($options))->setEnabled(true);
(new VulnerabilityPreferences($options))->setEnabled(true);
(new WordPressLoginSettings($options))->setRateMode('observe');
$options->set('amsec_alerts_enabled','1');
$rows=(new ActivityRepository($wpdb))->page(1,'security_setting_changed');
foreach($keys as $key){if(!in_array($key,array_column($rows,'target'),true)){throw new RuntimeException('Initial setting change missing: '.$key);}}
echo 'First writes through actual login/MCP/vulnerability/alert paths recorded.' . PHP_EOL;
