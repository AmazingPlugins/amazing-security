<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Integrity;

defined( 'ABSPATH' ) || exit;

use DateTimeImmutable;

final class Manifest {
	public function __construct( public readonly string $type, public readonly string $identity, public readonly string $sourceUrl, public readonly DateTimeImmutable $fetchedAt, public readonly string $algorithm, public readonly array $files ) {}
}
