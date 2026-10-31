<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Free\Recovery;

defined( 'ABSPATH' ) || exit;

/** HTTPS, manage_options, and a valid nonce. A missing piece blocks every change. */
final class Approval {
	public function __construct(
		private readonly bool $https,
		private readonly bool $canManage,
		private readonly bool $nonceValid,
	) {}

	public function denial(): ?string {
		if ( ! $this->https ) {
			return __( 'Recovery tools need HTTPS. No files were changed.', 'amsec-security-scanner' );
		}
		if ( ! $this->canManage ) {
			return __( 'You do not have permission to run recovery tools.', 'amsec-security-scanner' );
		}
		if ( ! $this->nonceValid ) {
			return __( 'The recovery form expired. Reload the page and try again.', 'amsec-security-scanner' );
		}
		return null;
	}
}
