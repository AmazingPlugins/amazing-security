<?php

// Run with: wp eval-file wp-content/plugins/amazing-security/tests/Integration/wordpress-smoke.php
use AmazingPlugins\Security\Checks\AdminAccountsCheck;
use AmazingPlugins\Security\Checks\DebugDisplayCheck;
use AmazingPlugins\Security\Checks\FileEditorCheck;
use AmazingPlugins\Security\Checks\HttpsAdminCheck;
use AmazingPlugins\Security\Checks\UpdatePostureCheck;
use AmazingPlugins\Security\Checks\WordPressValues;
use AmazingPlugins\Security\Findings\CheckResult;
use AmazingPlugins\Security\Findings\FindingsRepository;
use AmazingPlugins\Security\Scan\ScanContext;
use AmazingPlugins\Security\Scan\ScanCoordinator;
use AmazingPlugins\Security\Scan\ScanRun;

if (false !== get_option('amazing_security_latest_run', false)) {
    throw new RuntimeException('Activation unexpectedly created a run.');
}
$values = new WordPressValues();
$checks = [new UpdatePostureCheck($values), new DebugDisplayCheck($values), new FileEditorCheck($values), new HttpsAdminCheck($values), new AdminAccountsCheck($values)];
$run = (new ScanCoordinator())->run($checks, new ScanContext());
if (5 !== count($run->results)) {
    throw new RuntimeException('Expected five results.');
}
$repository = new FindingsRepository();
$repository->save($run);
$repository->save($run);
$stored = $repository->latest();
if (!$stored instanceof ScanRun || $stored->toArray() !== $run->toArray()) {
    throw new RuntimeException('Stored run differs from the scan.');
}
$reject_update = static fn($new_value, $old_value) => $old_value;
add_filter('pre_update_option_amazing_security_latest_run', $reject_update, 10, 2);
try {
    $repository->save(new ScanRun($run->startedAt, new DateTimeImmutable('2030-01-01T00:00:00Z'), $run->results, $run->partial));
    throw new RuntimeException('Failed option write unexpectedly succeeded.');
} catch (RuntimeException $error) {
    if ('Could not update scan run.' !== $error->getMessage()) {
        throw $error;
    }
} finally {
    remove_filter('pre_update_option_amazing_security_latest_run', $reject_update, 10);
}
if ($repository->latest()->toArray() !== $run->toArray()) {
    throw new RuntimeException('Failed save changed the previous report.');
}
wp_set_current_user(0);
if (current_user_can('manage_options')) {
    throw new RuntimeException('Anonymous user can manage options.');
}
$existing_editor = get_user_by('login', 'security_test_editor');
$editor_id = $existing_editor ? $existing_editor->ID : wp_insert_user(['user_login' => 'security_test_editor', 'user_pass' => wp_generate_password(32), 'user_email' => 'editor@example.invalid', 'role' => 'editor']);
if (is_wp_error($editor_id)) {
    throw new RuntimeException('Could not create editor test user.');
}
wp_set_current_user($editor_id);
if (current_user_can('manage_options')) {
    throw new RuntimeException('Editor can manage options.');
}
wp_set_current_user(1);
if (!current_user_can('manage_options')) {
    throw new RuntimeException('Owner cannot manage options.');
}
echo 'WordPress smoke: five checks, persistence and role gates passed.' . PHP_EOL;
