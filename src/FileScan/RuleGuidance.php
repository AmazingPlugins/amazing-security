<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\FileScan;

final class RuleGuidance {
	public static function forRule( string $id ): string {
		return match ( $id ) {
			'AS-PHP-001', 'AS-PHP-006' => 'Decoded data reaches eval, which can run PHP code. Ask the developer why executable code is encoded and compare this file with its exact published release.',
			'AS-PHP-002', 'AS-PHP-014' => 'A request value reaches a system command directly. Ask the developer to verify authorization, validation, and whether a shell command is necessary.',
			'AS-PHP-003' => 'A remote response selects a path for include or require. Confirm which local file can be selected and why. This pattern alone does not mean the remote response is executed as code.',
			'AS-PHP-004', 'AS-PHP-007', 'AS-PHP-016' => 'A visitor-controlled value reaches eval directly. Ask the developer to remove that code-execution path or explain the controls that make it safe.',
			'AS-PHP-005' => 'A request value selects an included file. Ask the developer to check that only an explicit list of intended local files can be loaded.',
			'AS-PHP-008', 'AS-PHP-012', 'AS-PHP-013' => 'A visitor-controlled destination may send people to another site. Ask the developer to validate destinations and consider wp_safe_redirect for local redirects.',
			'AS-PHP-009', 'AS-PHP-015' => 'A hidden external link can be SEO spam, but widgets and templates can also contain one. Confirm who added the link and why it is hidden.',
			'AS-PHP-010' => 'Untrusted serialized data can construct PHP objects. Ask the developer to review authentication and data provenance and consider JSON for untrusted input. This match does not establish exploitability.',
			'AS-PHP-011', 'AS-PHP-017' => 'A request value chooses the callback to run. Ask the developer to use an explicit allowlist and verify permissions before invoking it.',
			'AS-PHP-018' => 'A request value reaches assert directly. Ask the developer to remove that path. A second variable between the request and assert is not matched.',
			'AS-PHP-019' => 'Rotated text reaches eval. Ask the developer why executable code is encoded. Other encodings are not matched by this rule.',
			'AS-PHP-020' => 'A request value selects the file being written. Ask the developer to use a fixed path. A second variable between the request and the write is not matched.',
			'AS-PHP-021' => 'Request data is expanded into local variables. Ask the developer to read named fields instead. A second variable between the request and extract is not matched.',
			'AS-PHP-022' => 'Request data is parsed into local variables. Ask the developer to read named fields instead. A second variable between the request and parse_str is not matched.',
			'AS-PHP-023' => 'assert is stored in a variable and called with request data within six assignments. Ask the developer to remove that path. A seventh assignment is not matched.',
			'AS-PHP-024' => 'Request data reaches extract through up to six variables. Ask the developer to read named fields. A seventh assignment is not matched.',
			'AS-PHP-025' => 'Request data reaches parse_str through up to six variables. Ask the developer to read named fields. A seventh assignment is not matched.',
			'AS-PHP-026' => 'Request data selects a file through up to six variables. Ask the developer to use a fixed path. A seventh assignment is not matched.',
			'AS-PHP-027' => 'Request data is passed to create_function directly or through three variables. Ask the developer to remove that call. A fourth copied variable is not matched.',
			'AS-PHP-028' => 'A preg_replace pattern uses the old e modifier, which runs its replacement as code. Ask the developer to remove that modifier. A pattern stored in two variables is matched. A third copied variable is not matched.',
			'AS-PHP-029' => 'move_uploaded_file builds its destination from two strings around a name in the same call. Ask the developer which directory receives it and which extensions are allowed. A single destination string is not matched.',
			'AS-PHP-030' => 'file_put_contents writes $_POST or $_REQUEST to a string path in the same statement. Ask the developer to write only to a fixed path. $_GET, and a request value used only in another statement, are not matched.',
			'AS-PHP-031' => 'shell_exec or passthru joins a string in front of a request value in the same statement. Ask the developer to remove that command path. A request value passed alone is a different rule, and exec is not matched.',
			'AS-PHP-032' => 'copy reads a request value into a string path in the same call. Ask the developer which directory receives that file. A variable destination, a joined path, and a cookie value are not matched.',
			'AS-PHP-033' => 'fopen is called with a request value in the same statement. Ask the developer to open a fixed local path. A variable path and a cookie value are not matched.',
			'AS-PHP-034' => 'A Refresh header sends the browser to a request value. Ask the developer to allow only known local addresses. A fixed URL and a variable destination are not matched.',
			'AS-PHP-035' => 'readfile is called with a request value in the same statement. Ask the developer to read a fixed local path. A variable path and a cookie value are not matched.',
			'AS-PHP-036' => 'eval runs the body of an HTTP response in the same statement. Ask the developer to remove that path. One assignment then eval is covered by AS-PHP-038. One copy then eval is AS-PHP-040.',
			'AS-PHP-037' => 'include or require loads a data:// stream in the same statement. Ask the developer to include a fixed local file. One assignment then include is covered by AS-PHP-039. One copy then include is AS-PHP-041.',
			'AS-PHP-038' => 'An HTTP response body is stored in one variable and then evaluated. Ask the developer to remove that path. One copied variable then eval is AS-PHP-040. A third hop is not matched.',
			'AS-PHP-039' => 'A data:// string is stored in one variable and then loaded with include or require. Ask the developer to include a fixed local file. One copied variable then include is AS-PHP-041. A third hop is not matched.',
			'AS-PHP-040' => 'An HTTP response body is copied once and then evaluated. Ask the developer to remove that path. A third hop is not matched.',
			'AS-PHP-041' => 'A data:// string is copied once and then loaded with include or require. Ask the developer to include a fixed local file. A third hop is not matched.',
			default => 'Compare this file with its trusted release and ask its developer to explain the flagged behavior.',
		};
	}
}
