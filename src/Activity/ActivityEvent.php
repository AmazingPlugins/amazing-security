<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Activity;

final class ActivityEvent {
	public const TYPES = array( 'login_succeeded', 'login_failed', 'user_created', 'user_deleted', 'user_role_changed', 'plugin_activated', 'plugin_deactivated', 'plugin_updated', 'theme_switched', 'theme_updated', 'security_setting_changed', 'sessions_revoked', 'password_reset_required', 'password_reset_cleared', 'totp_policy_changed', 'totp_grace_granted', 'baseline_approved', 'bot_policy_changed' );

	public function __construct( public readonly string $event, public readonly int $actorId, public readonly int $userId, public readonly string $target, public readonly int $createdAt ) {
		if ( ! in_array( $event, self::TYPES, true ) || $actorId < 0 || $userId < 0 || $createdAt < 1 || strlen( $target ) > 190 || ! preg_match( '~^[a-zA-Z0-9_./-]*$~D', $target ) || str_contains( $target, '..' ) ) {
			throw new \InvalidArgumentException( 'Invalid activity event.' );
		}
	}

	public function row(): array {
		return array(
			'event'      => $this->event,
			'actor_id'   => $this->actorId,
			'user_id'    => $this->userId,
			'target'     => $this->target,
			'created_at' => $this->createdAt,
		);
	}
}
