<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\FileScan;

final class RuleGuidance {
	public static function forRule( string $id ): string {
		return match ( $id ) {
			'AS-PHP-001', 'AS-PHP-006' => 'Decoded data reaches eval, which can run PHP code. Ask the developer why executable code is encoded and compare this file with its exact published release.',
			'AS-PHP-002' => 'A request value reaches a system command directly. Ask the developer to verify authorization, validation, and whether a shell command is necessary.',
			'AS-PHP-003' => 'A remote response selects a path for include or require. Confirm which local file can be selected and why. This pattern alone does not mean the remote response is executed as code.',
			'AS-PHP-004', 'AS-PHP-007' => 'A visitor-controlled value reaches eval directly. Ask the developer to remove that code-execution path or explain the controls that make it safe.',
			'AS-PHP-005' => 'A request value selects an included file. Ask the developer to check that only an explicit list of intended local files can be loaded.',
			'AS-PHP-008', 'AS-PHP-012' => 'A visitor-controlled destination may send people to another site. Ask the developer to validate destinations and consider wp_safe_redirect for local redirects.',
			'AS-PHP-009' => 'A hidden external link can be SEO spam, but widgets and templates can also contain one. Confirm who added the link and why it is hidden.',
			'AS-PHP-010' => 'Untrusted serialized data can construct PHP objects. Ask the developer to review authentication and data provenance and consider JSON for untrusted input. This match does not establish exploitability.',
			'AS-PHP-011' => 'A request value chooses the callback to run. Ask the developer to use an explicit allowlist and verify permissions before invoking it.',
			default => 'Compare this file with its trusted release and ask its developer to explain the flagged behavior.',
		};
	}
}
