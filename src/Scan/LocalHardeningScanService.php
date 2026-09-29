<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Scan;

use AmazingPlugins\Security\Checks\AdminAccountsCheck;
use AmazingPlugins\Security\Checks\DebugDisplayCheck;
use AmazingPlugins\Security\Checks\FileEditorCheck;
use AmazingPlugins\Security\Checks\HttpsAdminCheck;
use AmazingPlugins\Security\Checks\UpdatePostureCheck;
use AmazingPlugins\Security\Checks\WordPressValues;
use AmazingPlugins\Security\Findings\FindingsRepository;
use Closure;

final class LocalHardeningScanService {
	private readonly Closure $execute;
	private readonly Closure $save;

	public function __construct( ?callable $execute = null, ?callable $save = null ) {
		$this->execute = Closure::fromCallable(
			$execute ?? static function (): ScanRun {
				$values = new WordPressValues();
				$checks = array( new UpdatePostureCheck( $values ), new DebugDisplayCheck( $values ), new FileEditorCheck( $values ), new HttpsAdminCheck( $values ), new AdminAccountsCheck( $values ) );
				return ( new ScanCoordinator() )->run( $checks, new ScanContext() );
			}
		);
		$this->save    = Closure::fromCallable( $save ?? static fn( ScanRun $run ) => ( new FindingsRepository() )->save( $run ) );
	}

	public function run(): ScanRun {
		$run = ( $this->execute )();
		( $this->save )( $run );
		return $run;
	}
}
