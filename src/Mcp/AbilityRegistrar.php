<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Mcp;

use Closure;

final class AbilityRegistrar {
	private readonly Closure $canManage;
	private readonly Closure $userId;

	public function __construct( private readonly McpPreferences $preferences, private readonly FindingsGateway $findings, private readonly ScanGateway $scans, ?callable $canManage = null, ?callable $userId = null ) {
		$this->canManage = Closure::fromCallable( $canManage ?? static fn(): bool => current_user_can( 'manage_options' ) );
		$this->userId    = Closure::fromCallable( $userId ?? static fn(): int => get_current_user_id() );
	}

	public function allowed(): bool {
		return $this->preferences->enabled() && ( $this->canManage )();
	}

	public function registerCategory(): void {
		if ( function_exists( 'wp_register_ability_category' ) ) {
			wp_register_ability_category(
				'amazing-security',
				array(
					'label'       => 'Amazing Security',
					'description' => 'Security findings and bounded checks for this site.',
				)
			);
		}
	}

	public function registerAbilities(): void {
		if ( ! function_exists( 'wp_register_ability' ) ) {
			return;
		}
		foreach ( $this->definitions() as $name => $definition ) {
			wp_register_ability( $name, $definition );
		}
	}

	public function definitions(): array {
		$schemas = array(
			'list-findings' => array(
				'type'                 => 'object',
				'properties'           => array(
					'offset' => array(
						'type'    => 'integer',
						'minimum' => 0,
						'maximum' => 1000,
					),
					'limit'  => array(
						'type'    => 'integer',
						'minimum' => 1,
						'maximum' => 100,
					),
				),
				'additionalProperties' => false,
			),
			'get-finding'   => array(
				'type'                 => 'object',
				'properties'           => array(
					'finding_id' => array(
						'type'    => 'string',
						'pattern' => '^[a-f0-9]{32}$',
					),
				),
				'required'             => array( 'finding_id' ),
				'additionalProperties' => false,
			),
			'start-scan'    => array(
				'type'                 => 'object',
				'properties'           => array(
					'type' => array(
						'type' => 'string',
						'enum' => array( 'hardening' ),
					),
				),
				'required'             => array( 'type' ),
				'additionalProperties' => false,
			),
			'get-scan'      => array(
				'type'                 => 'object',
				'properties'           => array(
					'scan_id' => array(
						'type'    => 'string',
						'pattern' => '^[a-f0-9]{32}$',
					),
				),
				'required'             => array( 'scan_id' ),
				'additionalProperties' => false,
			),
		);
		$labels  = array(
			'list-findings' => 'List security findings',
			'get-finding'   => 'Get a security finding',
			'start-scan'    => 'Run local hardening checks',
			'get-scan'      => 'Get a local hardening scan',
		);
		$out     = array();
		foreach ( $schemas as $short => $schema ) {
			$out[ 'amazing-security/' . $short ] = array(
				'label'               => $labels[ $short ],
				'description'         => $labels[ $short ] . ' for an authenticated site administrator.',
				'category'            => 'amazing-security',
				'input_schema'        => $schema,
				'execute_callback'    => fn( $input = array() ): array => $this->execute( $short, $input ),
				'permission_callback' => fn(): bool => $this->allowed(),
				'meta'                => array(
					'mcp' => array(
						'public' => $this->preferences->enabled(),
						'type'   => 'tool',
					),
				),
			);
		}
		return $out;
	}

	public function execute( string $ability, mixed $input ): array {
		if ( ! $this->allowed() ) {
			return array(
				'schema_version' => 1,
				'state'          => 'forbidden',
			);
		}
		if ( ! is_array( $input ) ) {
			return array(
				'schema_version' => 1,
				'state'          => 'invalid_input',
			);
		}
		switch ( $ability ) {
			case 'list-findings':
				if ( array_diff( array_keys( $input ), array( 'offset', 'limit' ) ) || ! is_int( $input['offset'] ?? 0 ) || ! is_int( $input['limit'] ?? 50 ) || ( $input['offset'] ?? 0 ) < 0 || ( $input['offset'] ?? 0 ) > 1000 || ( $input['limit'] ?? 50 ) < 1 || ( $input['limit'] ?? 50 ) > 100 ) {
					break;
				}
				return $this->findings->list( $input['offset'] ?? 0, $input['limit'] ?? 50 );
			case 'get-finding':
				if ( array_keys( $input ) !== array( 'finding_id' ) || ! is_string( $input['finding_id'] ) || ! preg_match( '/^[a-f0-9]{32}$/D', $input['finding_id'] ) ) {
					break;
				}
				$finding = $this->findings->get( $input['finding_id'] );
				return null === $finding ? array(
					'schema_version' => 1,
					'state'          => 'missing',
				) : array(
					'schema_version' => 1,
					'state'          => 'found',
					'finding'        => $finding,
				);
			case 'start-scan':
				if ( array_keys( $input ) !== array( 'type' ) || 'hardening' !== $input['type'] ) {
					break;
				}
				return $this->scans->start( ( $this->userId )(), 'hardening' );
			case 'get-scan':
				if ( array_keys( $input ) !== array( 'scan_id' ) || ! is_string( $input['scan_id'] ) || ! preg_match( '/^[a-f0-9]{32}$/D', $input['scan_id'] ) ) {
					break;
				}
				return $this->scans->get( $input['scan_id'] );
		}
		return array(
			'schema_version' => 1,
			'state'          => 'invalid_input',
		);
	}
}
