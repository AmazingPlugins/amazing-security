<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Free\Recovery;

/** A recovery attempt. Failures never carry a partial SQL body. */
final class ChangeResult {
	private function __construct(
		public readonly bool $ok,
		public readonly string $message,
		public readonly string $body,
	) {}

	public static function success( string $message, string $body = '' ): self {
		return new self( true, $message, $body );
	}

	public static function failure( string $message ): self {
		return new self( false, $message, '' );
	}
}
