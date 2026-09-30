<?php
namespace AmazingPlugins\Security\Tests\Unit\Passkeys;
use PHPUnit\Framework\TestCase;
use AmazingPlugins\Security\Passkeys\{Base64Url,PasskeyContext,PasskeyVerifier};
final class VerifierTest extends TestCase {
 private string|false $previousRandFile;
 private string $randFile;
 protected function setUp():void { if(!defined('ABSPATH'))define('ABSPATH',dirname(__DIR__,3).'/');$this->previousRandFile=getenv('RANDFILE');$this->randFile=tempnam(sys_get_temp_dir(),'amsec-rand-');chmod($this->randFile,0600);putenv('RANDFILE='.$this->randFile); }
 protected function tearDown():void { putenv($this->previousRandFile===false?'RANDFILE':'RANDFILE='.$this->previousRandFile);if(is_file($this->randFile))unlink($this->randFile); }
 private function material():array {
 $private=openssl_pkey_new(['private_key_type'=>OPENSSL_KEYTYPE_EC,'curve_name'=>'prime256v1']);$public=openssl_pkey_get_details($private);return [$private,$public];
 }
 private function client(bool $create,string $challenge,string $origin='https://example.com'):string {return json_encode(['type'=>$create?'webauthn.create':'webauthn.get','challenge'=>$challenge,'origin'=>$origin,'crossOrigin'=>false]);}
 private function envelope(string $id,array $response):string {return json_encode(['id'=>Base64Url::encode($id),'rawId'=>Base64Url::encode($id),'type'=>'public-key','response'=>array_map([Base64Url::class,'encode'],$response)]);}
 private function register(string $id,string $challenge,array $public,string $origin='https://example.com',int $flag=0x45):string {
 $cose="\xa5\x01\x02\x03\x26\x20\x01\x21\x58\x20".$public['ec']['x']."\x22\x58\x20".$public['ec']['y'];
 $auth=hash('sha256','example.com',true).chr($flag).pack('N',0).str_repeat("\0",16).pack('n',strlen($id)).$id.$cose;
 $att="\xa3\x63fmt\x64none\x67attStmt\xa0\x68authData\x59".pack('n',strlen($auth)).$auth;
 return $this->envelope($id,['clientDataJSON'=>$this->client(true,$challenge,$origin),'attestationObject'=>$att]);
 }
 private function assertion(string $id,string $handle,string $challenge,\OpenSSLAsymmetricKey $private,int $counter=0,string $origin='https://example.com',int $flag=0x05,string $rp='example.com'):string {
 $client=$this->client(false,$challenge,$origin);$auth=hash('sha256',$rp,true).chr($flag).pack('N',$counter);openssl_sign($auth.hash('sha256',$client,true),$signature,$private,OPENSSL_ALGO_SHA256);
 return $this->envelope($id,['clientDataJSON'=>$client,'authenticatorData'=>$auth,'signature'=>$signature,'userHandle'=>$handle]);
 }
 public function testGeneratedResidentUvEs256MaterialRegistersAndVerifiesZeroCounterAssertion():void {
 [$private,$public]=$this->material();$id=random_bytes(32);$handle=random_bytes(32);$challenge=Base64Url::encode(random_bytes(32));$v=new PasskeyVerifier();$ctx=PasskeyContext::fromSiteUrl('https://example.com');
 $registered=$v->registration($this->register($id,$challenge,$public),$ctx,$challenge);self::assertNotNull($registered);self::assertSame($id,$registered['credential_id']);self::assertSame($public['key'],$registered['public_key']);self::assertSame(0,$registered['counter']);self::assertFalse($registered['backup_eligible']);
 $r=$v->assertion($this->assertion($id,$handle,$challenge,$private),$ctx,$challenge,$id,$handle,$registered['public_key'],0,false);self::assertSame(0,$r['counter']);
 }
 public function testExactOriginChallengeUvRpOwnershipKeyAndCounterBoundariesAreRefused():void {
 [$private,$public]=$this->material();[, $other]=$this->material();$id=random_bytes(32);$handle=random_bytes(32);$challenge=Base64Url::encode(random_bytes(32));$v=new PasskeyVerifier();$ctx=PasskeyContext::fromSiteUrl('https://example.com');
 foreach(['https://evilexample.com','https://sub.example.com','https://example.com:8443','http://example.com'] as $origin){self::assertNull($v->registration($this->register($id,$challenge,$public,$origin),$ctx,$challenge));self::assertNull($v->assertion($this->assertion($id,$handle,$challenge,$private,0,$origin),$ctx,$challenge,$id,$handle,$public['key'],0,false));}
 self::assertNull($v->registration($this->register($id,$challenge,$public),$ctx,Base64Url::encode(random_bytes(32))));self::assertNull($v->registration($this->register($id,$challenge,$public,'https://example.com',0x41),$ctx,$challenge));
 $good=$this->assertion($id,$handle,$challenge,$private);
 foreach([[$id,$handle,$other['key'],0,false],[random_bytes(32),$handle,$public['key'],0,false],[$id,random_bytes(32),$public['key'],0,false],[$id,$handle,$public['key'],1,false],[$id,$handle,$public['key'],0,true],[$id,$handle,'bad key',0,false],[$id,$handle,$public['key'],-1,false]] as $args)self::assertNull($v->assertion($good,$ctx,$challenge,...$args));
 self::assertNull($v->assertion($good,$ctx,Base64Url::encode(random_bytes(32)),$id,$handle,$public['key'],0,false));
 foreach([$this->assertion($id,$handle,$challenge,$private,0,'https://example.com',0x01),$this->assertion($id,$handle,$challenge,$private,0,'https://example.com',0x05,'evil.com')] as $bad)self::assertNull($v->assertion($bad,$ctx,$challenge,$id,$handle,$public['key'],0,false));
 $tampered=json_decode($good,true);$tampered['response']['signature']=Base64Url::encode(random_bytes(70));self::assertNull($v->assertion(json_encode($tampered),$ctx,$challenge,$id,$handle,$public['key'],0,false));
 self::assertSame(2,$v->assertion($this->assertion($id,$handle,$challenge,$private,2),$ctx,$challenge,$id,$handle,$public['key'],1,false)['counter']);self::assertNull($v->assertion($this->assertion($id,$handle,$challenge,$private,1),$ctx,$challenge,$id,$handle,$public['key'],1,false));
 }
 public function testOffCurvePublicPointIsNotAcceptedForStorage():void {
 $id=random_bytes(32);$challenge=Base64Url::encode(random_bytes(32));$public=['ec'=>['x'=>str_repeat("\0",32),'y'=>str_repeat("\0",32)]];
 self::assertNull((new PasskeyVerifier())->registration($this->register($id,$challenge,$public),PasskeyContext::fromSiteUrl('https://example.com'),$challenge));
 }
}
