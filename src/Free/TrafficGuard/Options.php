<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Free\TrafficGuard;

/** Option names for the free traffic controls. */
final class Options {
	public const HOSTNAMES = 'amsec_block_hostnames';
	public const AGENTS    = 'amsec_block_agents';
	public const REFERRERS = 'amsec_block_referrers';
	public const LIVE      = 'amsec_live_traffic';
	public const LIVE_ROWS = 'amsec_live_traffic_rows';
	public const HOTLINK   = 'amsec_hotlink';
}
