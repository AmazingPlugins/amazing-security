<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Login;

interface LoginSettings {
	public function rateMode(): string;
	public function setRateMode( string $mode ): void;
	public function xmlRpcAuthDisabled(): bool;
	public function setXmlRpcAuthDisabled( bool $disabled ): void;
	public function eraseOnUninstall(): bool;
	public function setEraseOnUninstall( bool $erase ): void;
}
