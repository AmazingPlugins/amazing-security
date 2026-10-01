<?php
namespace AmazingPlugins\Security\Tests\Unit\Passkeys;
use PHPUnit\Framework\TestCase;
use AmazingPlugins\Security\Passkeys\{PasskeyContext,Base64Url,PasskeyEnvelope};
final class ContextEnvelopeTest extends TestCase {
 public function testOriginUsesConfiguredHttpsDomainAndExactPortNotSuffix():void {
 $c=PasskeyContext::fromSiteUrl('https://Example.com:8443/wordpress');self::assertSame('example.com',$c->rpId());self::assertSame('https://example.com:8443',$c->origin());self::assertTrue($c->acceptOrigin('https://example.com:8443'));foreach(['https://evilexample.com:8443','https://sub.example.com:8443','https://example.com','http://example.com:8443','https://example.com:8443/','https://example.com:8443.evil',null,[]] as $origin)self::assertFalse($c->acceptOrigin($origin));self::assertSame('https://localhost:18890',PasskeyContext::fromSiteUrl('https://localhost:18890')->origin());self::assertSame('https://example.com',PasskeyContext::fromSiteUrl('https://example.com:443')->origin());
 foreach(['http://example.com','https://user@example.com','https://user:password@example.com','https://127.0.0.1','https://[::1]','https://example.com.','https://éxample.com','https://example.com?query=x','https://example.com#fragment','https://bad_host.com','https://-bad.com','https://example.com:0',"https://example.com\n"] as $url)self::assertNull(PasskeyContext::fromSiteUrl($url));self::assertNotSame($c->fingerprint(),PasskeyContext::fromSiteUrl('https://example.com')->fingerprint());
 }
 public function testDirectoryIsPartOfTheAdminDestinationAndSiteBindingButNotTheWebAuthnOrigin(): void {
 $root = PasskeyContext::fromSiteUrl('https://example.com/');
 $nested = PasskeyContext::fromSiteUrl('https://Example.com/wordpress/');
 self::assertSame('https://example.com', $root->origin());
 self::assertSame('https://example.com/wp-admin/', $root->adminUrl());
 self::assertSame('https://example.com', $nested->origin());
 self::assertSame('example.com', $nested->rpId());
 self::assertSame('https://example.com/wordpress/wp-admin/', $nested->adminUrl());
 self::assertNotSame($root->fingerprint(), $nested->fingerprint());
 self::assertTrue($nested->acceptOrigin('https://example.com'));
 foreach (['https://example.com/wordpress/../secret', 'https://example.com//wordpress', 'https://example.com/word press'] as $url) {
  self::assertNull(PasskeyContext::fromSiteUrl($url));
 }
 }
 public function testCanonicalBinaryDecodingRejectsPaddingDiscardedBitsAndOversize():void {
 for($n=0;$n<20;$n++){$bytes=$n===0?'':random_bytes($n);self::assertSame($bytes,Base64Url::decode(Base64Url::encode($bytes),20));}
 foreach(['AA=','AA==','AB','A','+/==','%2f',"AA\n",[],null,str_repeat('A',29)] as $encoded)self::assertNull(Base64Url::decode($encoded,20));self::assertNull(Base64Url::decode('AAAA',2));
 }
 private function registration():array { $id=Base64Url::encode(random_bytes(32));return ['id'=>$id,'rawId'=>$id,'type'=>'public-key','response'=>['clientDataJSON'=>Base64Url::encode('{}'),'attestationObject'=>Base64Url::encode('binary')]]; }
 public function testEnvelopeKeepsOnlyValidatedBinaryFieldsAndRefusesShapeChanges():void {
 $payload=$this->registration();$e=new PasskeyEnvelope();$record=$e->read(json_encode($payload),true);self::assertSame(['credential_id','client_data','attestation'],array_keys($record));self::assertSame(32,strlen($record['credential_id']));
 foreach([array_replace($payload,['id'=>'different']),array_replace($payload,['type'=>'password']),$payload+['user_id'=>1],array_replace($payload,['response'=>[]]),array_replace($payload,['response'=>['clientDataJSON'=>Base64Url::encode(str_repeat('a',8193)),'attestationObject'=>Base64Url::encode('binary')]])] as $bad)self::assertNull($e->read(json_encode($bad),true));self::assertNull($e->read(str_repeat('x',98305),true));self::assertNull($e->read('[]',true));
 $id=$payload['id'];$get=['rawId'=>$id,'id'=>$id,'type'=>'public-key','response'=>['userHandle'=>Base64Url::encode(random_bytes(32)),'signature'=>Base64Url::encode(random_bytes(64)),'authenticatorData'=>Base64Url::encode(random_bytes(37)),'clientDataJSON'=>Base64Url::encode('{}')]];self::assertNotNull($e->read(json_encode($get),false));$get['response']['userHandle']=Base64Url::encode(random_bytes(31));self::assertNull($e->read(json_encode($get),false));
 }
 public function testSignedClientDataRequiresExactOriginTypeChallengeAndNonembeddedContext():void {
 $c=PasskeyContext::fromSiteUrl('https://example.com');$challenge=Base64Url::encode(random_bytes(32));$s=['type'=>'webauthn.get','challenge'=>$challenge,'origin'=>$c->origin(),'crossOrigin'=>false];$e=new PasskeyEnvelope();self::assertTrue($e->clientData(json_encode($s),$c,false,$challenge));foreach([['origin'=>'https://evilexample.com'],['origin'=>'https://sub.example.com'],['type'=>'webauthn.create'],['challenge'=>Base64Url::encode(random_bytes(32))],['crossOrigin'=>true],['crossOrigin'=>'false'],['topOrigin'=>$c->origin()]] as $change)self::assertFalse($e->clientData(json_encode(array_replace($s,$change)),$c,false,$challenge));
 }
 public function testClientDataRequiresA32ByteServerChallenge():void {$c=PasskeyContext::fromSiteUrl('https://example.com');$e=new PasskeyEnvelope();foreach([0,1,31,33] as $length){$challenge=Base64Url::encode($length===0?'':random_bytes($length));$s=['type'=>'webauthn.get','origin'=>$c->origin(),'challenge'=>$challenge];self::assertFalse($e->clientData(json_encode($s),$c,false,$challenge));}}

}
