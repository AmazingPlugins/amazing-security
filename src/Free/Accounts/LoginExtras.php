<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Free\Accounts;

defined( 'ABSPATH' ) || exit;

/** Posted sign-in limit and XML-RPC choices. Unknown values are ignored. */
final class LoginExtras {
	public const RATE = 'amsec_login_rate_mode';

	public const XMLRPC = 'amsec_login_xmlrpc_disabled';

	public static function rate( mixed $value ): ?string {
		$mode = is_string( $value ) ? $value : '';
		return in_array( $mode, array( 'off', 'observe', 'block' ), true ) ? $mode : null;
	}

	public static function xmlrpc( mixed $value ): ?string {
		$flag = is_string( $value ) ? $value : '';
		return in_array( $flag, array( '0', '1' ), true ) ? $flag : null;
	}
}
