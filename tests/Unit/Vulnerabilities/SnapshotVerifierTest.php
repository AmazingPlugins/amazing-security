<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Vulnerabilities;

use AmazingPlugins\Security\Vulnerabilities\InstalledSoftware;
use AmazingPlugins\Security\Vulnerabilities\SnapshotVerifier;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

final class SnapshotVerifierTest extends TestCase {
	private string $privateKey;
	private string $publicKey;
	private array $inventory;

	protected function setUp(): void {
		putenv( 'RANDFILE=' . sys_get_temp_dir() . '/amsec-test-random-state' );
		$key = openssl_pkey_new( array( 'private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048 ) );
		self::assertNotFalse( $key );
		$this->privateKey = '';
		self::assertTrue( openssl_pkey_export( $key, $this->privateKey ) );
		$this->publicKey = openssl_pkey_get_details( $key )['key'];
		$this->inventory = array( new InstalledSoftware( 'core', 'wordpress', '6.9.4', true ) );
	}

	public function test_accepts_current_signed_complete_snapshot_bound_to_inventory(): void {
		$verifier = $this->verifier();
		$result   = $verifier->verify( $this->envelope( $this->payload( $verifier ) ), $this->inventory, null );
		self::assertSame( 'accepted', $result->state );
		self::assertSame( 2, $result->snapshot->sequence );
	}

	public function test_rejects_tampering_even_when_json_remains_valid(): void {
		$verifier = $this->verifier();
		$envelope = json_decode( $this->envelope( $this->payload( $verifier ) ), true );
		$payload  = json_decode( base64_decode( $envelope['payload_b64'], true ), true );
		$payload['sequence'] = 3;
		$envelope['payload_b64'] = base64_encode( json_encode( $payload ) );
		self::assertSame( 'unknown', $verifier->verify( json_encode( $envelope ), $this->inventory, null )->state );
	}

	public function test_accepts_the_same_signed_fields_in_different_json_key_order(): void {
		$verifier = $this->verifier();
		$payload  = $this->payload( $verifier );
		$payload  = array_reverse( $payload, true );
		$envelope = json_decode( $this->envelope( $payload ), true );
		$envelope = array_reverse( $envelope, true );
		self::assertSame( 'accepted', $verifier->verify( json_encode( $envelope ), $this->inventory, null )->state );
	}

	public function test_rejects_stale_incomplete_wrong_inventory_and_replayed_snapshots(): void {
		$verifier = $this->verifier();
		$valid    = $verifier->verify( $this->envelope( $this->payload( $verifier ) ), $this->inventory, null )->snapshot;
		$variants = array(
			array( 'expires_at' => '2026-09-27T00:00:00Z' ),
			array( 'complete' => false ),
			array( 'inventory_hash' => str_repeat( '0', 64 ) ),
		);
		foreach ( $variants as $override ) {
			self::assertSame( 'unknown', $verifier->verify( $this->envelope( array_merge( $this->payload( $verifier ), $override ) ), $this->inventory, null )->state );
		}
		self::assertSame( 'unknown', $verifier->verify( $this->envelope( $this->payload( $verifier ) ), $this->inventory, $valid )->state );
	}

	public function test_rejects_unknown_key_oversize_and_invalid_record_shape(): void {
		$verifier = $this->verifier();
		$payload  = $this->payload( $verifier );
		$payload['records'] = array( array( 'title' => '<script>' ) );
		self::assertSame( 'unknown', $verifier->verify( $this->envelope( $payload ), $this->inventory, null )->state );
		$envelope = json_decode( $this->envelope( $this->payload( $verifier ) ), true );
		$envelope['key_id'] = 'other';
		self::assertSame( 'unknown', $verifier->verify( json_encode( $envelope ), $this->inventory, null )->state );
		self::assertSame( 'unknown', $verifier->verify( str_repeat( 'x', 2 * 1024 * 1024 + 1 ), $this->inventory, null )->state );
	}

	private function verifier(): SnapshotVerifier {
		return new SnapshotVerifier( array( 'fixture' => $this->publicKey ), new DateTimeImmutable( '2026-09-29T03:00:00Z' ) );
	}

	private function payload( SnapshotVerifier $verifier ): array {
		return array(
			'schema' => 1, 'sequence' => 2,
			'generated_at' => '2026-09-29T02:00:00Z', 'expires_at' => '2026-09-30T02:00:00Z',
			'provider' => 'wordfence-v3-production', 'inventory_hash' => $verifier->inventoryHash( $this->inventory ),
			'complete' => true, 'records' => array(),
		);
	}

	private function envelope( array $payload ): string {
		$bytes = json_encode( $payload, JSON_THROW_ON_ERROR );
		openssl_sign( $bytes, $signature, $this->privateKey, OPENSSL_ALGO_SHA256 );
		return json_encode( array( 'key_id' => 'fixture', 'payload_b64' => base64_encode( $bytes ), 'signature_b64' => base64_encode( $signature ) ), JSON_THROW_ON_ERROR );
	}
}
