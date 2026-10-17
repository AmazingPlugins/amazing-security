<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Fixes;

defined( 'ABSPATH' ) || exit;

final class RecipeCatalog {
	public function transition( string $recipeId, string $currentMode ): ?array {
		return match ( $recipeId . ':' . $currentMode ) {
			'login-rate-observe:off' => array(
				'before' => 'off',
				'after'  => 'observe',
			),
			'login-rate-block:observe' => array(
				'before' => 'observe',
				'after'  => 'block',
			),
			default => null,
		};
	}
}
