<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Free\Detect;

use AmazingPlugins\Security\FileScan\BundledRulePack;
use AmazingPlugins\Security\FileScan\RuleMatcher;
use PHPUnit\Framework\TestCase;

final class RulePatternTest extends TestCase {
	public function test_new_rules_match_and_miss(): void {
		$cases = array(
			array( "<?php move_uploaded_file(\$tmp, 'wp-content/uploads/' . \$name . '.php');", array( 'AS-PHP-029' ) ),
			array( "<?php move_uploaded_file(\$tmp, 'wp-content/uploads/shell.php');", array() ),
			array( "<?php file_put_contents('wp-content/uploads/drop.php', \$_POST['body']);", array( 'AS-PHP-030' ) ),
			array( "<?php file_put_contents(\$dir . '.php', \$_REQUEST['body']);", array( 'AS-PHP-030' ) ),
			array( "<?php file_put_contents('wp-content/uploads/drop.php', \$_GET['body']);", array() ),
			array( "<?php \$body = \$_POST['body']; file_put_contents('wp-content/uploads/drop.php', \$body);", array() ),
			array( "<?php shell_exec('id ' . \$_POST['cmd']);", array( 'AS-PHP-031' ) ),
			array( "<?php passthru('id ' . \$_REQUEST['cmd']);", array( 'AS-PHP-031' ) ),
			array( "<?php shell_exec('id ' . \$cmd);", array() ),
			array( "<?php exec('id ' . \$_POST['cmd']);", array( 'AS-MAL-002' ) ),
			array( "<?php copy(\$_POST['url'], 'wp-content/uploads/drop.php');", array( 'AS-PHP-032' ) ),
			array( "<?php copy(\$_GET['url'], \$dest);", array() ),
			array( "<?php copy(\$_COOKIE['url'], 'wp-content/uploads/drop.php');", array() ),
			array( "<?php fopen(\$_REQUEST['path'], 'r');", array( 'AS-PHP-033' ) ),
			array( "<?php fopen(\$path, 'r');", array() ),
			array( "<?php fopen(\$_COOKIE['path'], 'r');", array() ),
			array( "<?php header('Refresh: 0;url=' . \$_GET['next']);", array( 'AS-PHP-034' ) ),
			array( "<?php header('Refresh: 0;url=https://example.com');", array() ),
			array( "<?php header('Refresh: 0;url=' . \$next);", array() ),
			array( "<?php readfile(\$_POST['path']);", array( 'AS-PHP-035' ) ),
			array( "<?php readfile(\$path);", array() ),
			array( "<?php readfile(\$_COOKIE['path']);", array() ),
			array( '<?php eval(wp_remote_retrieve_body($response));', array( 'AS-PHP-036' ) ),
			array( '<?php $body = wp_remote_retrieve_body($response); echo $body;', array() ),
			array( '<?php $body = wp_remote_retrieve_body($response); eval($body);', array( 'AS-PHP-038' ) ),
			array( '<?php $body = wp_remote_retrieve_body($response); $copy = $body; eval($copy);', array( 'AS-PHP-040' ) ),
			array( '<?php $body = wp_remote_retrieve_body($response); $copy = $body; $again = $copy; eval($again);', array( 'AS-PHP-042' ) ),
			array( '<?php $body = wp_remote_retrieve_body($response); $copy = $body; $again = $copy; $last = $again; eval($last);', array() ),
			array( "<?php include 'data://text/plain,<?php phpinfo();';", array( 'AS-PHP-037' ) ),
			array( "<?php \$stream = 'data://text/plain,hello'; echo \$stream;", array() ),
			array( "<?php \$stream = 'data://text/plain,hello'; include \$stream;", array( 'AS-PHP-039' ) ),
			array( "<?php \$stream = 'data://text/plain,hello'; include(\$stream);", array( 'AS-PHP-039' ) ),
			array( "<?php \$stream = 'data://text/plain,hello'; \$copy = \$stream; include \$copy;", array( 'AS-PHP-041' ) ),
			array( "<?php \$stream = 'data://text/plain,hello'; \$copy = \$stream; \$again = \$copy; include \$again;", array( 'AS-PHP-043' ) ),
			array( "<?php \$stream = 'data://text/plain,hello'; \$copy = \$stream; \$again = \$copy; \$last = \$again; include \$last;", array() ),
		);
		$matcher = new RuleMatcher( new BundledRulePack() );
		foreach ( $cases as $case ) {
			$hits = $matcher->match( $case[0], 'fixture.php' );
			self::assertSame( $case[1], array_column( $hits, 'ruleId' ), $case[0] );
		}
	}
}
