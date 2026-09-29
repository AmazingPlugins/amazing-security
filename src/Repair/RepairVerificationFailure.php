<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Repair;

use RuntimeException;

final class RepairVerificationFailure extends RuntimeException {
	public function __construct( public readonly RepairReceipt $receipt ) {
		parent::__construct( 'Replacement verification failed; private backup retained.' );
	}
}
