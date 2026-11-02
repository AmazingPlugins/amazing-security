<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Free\TrafficGuard;

defined( 'ABSPATH' ) || exit;

/** Option names for the free traffic controls. */
final class Options {
	public const HOSTNAMES = 'ironlatch_block_hostnames';
	public const AGENTS    = 'ironlatch_block_agents';
	public const REFERRERS = 'ironlatch_block_referrers';
	public const LIVE      = 'ironlatch_live_traffic';
	public const LIVE_ROWS = 'ironlatch_live_traffic_rows';
	public const HOTLINK   = 'ironlatch_hotlink';
}
