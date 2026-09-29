<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Vulnerabilities;

final class WordPressDirectFeedCache implements DirectFeedCache {
	public function get( string $key ): ?array {
		$value = get_transient( $this->name( $key ) );
		return is_array( $value ) && is_string( $value['body'] ?? null ) && is_int( $value['fetched_at'] ?? null ) ? $value : null;
	}

	public function put( string $key, string $body, int $fetchedAt ): void {
		set_transient(
			$this->name( $key ),
			array(
				'body'       => $body,
				'fetched_at' => $fetchedAt,
			),
			DAY_IN_SECONDS
		);
	}

	private function name( string $key ): string {
		return 'amsec_vuln_' . substr( hash( 'sha256', $key ), 0, 32 );
	}
}
