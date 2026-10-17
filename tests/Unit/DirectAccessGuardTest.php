<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit;

use PHPUnit\Framework\TestCase;

final class DirectAccessGuardTest extends TestCase {
	public function test_every_runtime_php_file_refuses_direct_access(): void {
		$root  = dirname( __DIR__, 2 );
		$files = new \RecursiveIteratorIterator( new \RecursiveDirectoryIterator( $root . '/src', \FilesystemIterator::SKIP_DOTS ) );
		$count = 0;
		foreach ( $files as $file ) {
			if ( 'php' !== $file->getExtension() ) {
				continue;
			}
			++$count;
			// The guard must be the first statement after the opening tag, declare, namespace and use lines.
			$code = (string) preg_replace( '~\A<\?php\s*|^\s*(//.*|/?\*.*|declare\(.*\);|namespace .*;|use .*;)\s*$~m', '', (string) file_get_contents( $file->getPathname() ) );
			self::assertMatchesRegularExpression( "/\\A\\s*(defined\\( 'ABSPATH' \\) \\|\\| exit;|if \\( ! defined\\( 'ABSPATH' \\) \\))/", $code, $file->getPathname() );
		}
		self::assertGreaterThan( 300, $count );
	}
}
