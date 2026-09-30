<?php
namespace AmazingPlugins\Security\Tests\Unit\Passkeys;
use PHPUnit\Framework\TestCase;
use AmazingPlugins\Security\Passkeys\{Base64Url,PasskeyContext,PasskeyPolicy,PasskeyCredential,PasskeyPending};
final class StateTest extends TestCase {
 private function pending(string $purpose='login'):array {return ['version'=>1,'purpose'=>$purpose,'user_id'=>$purpose==='login'?0:4,'session_hash'=>$purpose==='login'?'':str_repeat('a',64),'challenge'=>Base64Url::encode(random_bytes(32)),'ticket_hash'=>str_repeat('b',64),'binding_hash'=>str_repeat('c',64),'policy_revision'=>str_repeat('d',32),'context_revision'=>str_repeat('e',64),'created_at'=>1000,'expires_at'=>1300];}
 private function credential():array {
 $old=getenv('RANDFILE');$tmp=tempnam(sys_get_temp_dir(),'amsec-rand-');chmod($tmp,0600);putenv('RANDFILE='.$tmp);
 try {$key=openssl_pkey_new(['private_key_type'=>OPENSSL_KEYTYPE_EC,'curve_name'=>'prime256v1']);$public=openssl_pkey_get_details($key)['key'];}finally{putenv($old===false?'RANDFILE':'RANDFILE='.$old);unlink($tmp);}
 return ['version'=>1,'user_id'=>4,'credential_id'=>Base64Url::encode(random_bytes(32)),'user_handle'=>Base64Url::encode(random_bytes(32)),'public_key'=>$public,'origin'=>'https://example.com:8443','rp_id'=>'example.com','context_revision'=>PasskeyContext::fromSiteUrl('https://example.com:8443')->fingerprint(),'counter'=>0,'backup_eligible'=>true,'backed_up'=>false,'label'=>'Laptop','created_at'=>1000,'last_used_at'=>0,'revision'=>str_repeat('a',32)];
 }
 public function testExactPolicyDefaultsOffAndRejectsCoercionOrUnknownFields():void {
 $p=new PasskeyPolicy();self::assertFalse($p->read(null)['enabled']);$good=['version'=>1,'enabled'=>true,'revision'=>str_repeat('a',32)];self::assertSame($good,$p->read(json_encode($good)));
 foreach(['',[],str_repeat('x',2049),json_encode($good+['other'=>true]),json_encode(array_replace($good,['version'=>2])),json_encode(array_replace($good,['enabled'=>1])),json_encode(array_replace($good,['revision'=>str_repeat('A',32)]))] as $bad)self::assertNull($p->read($bad));self::assertNotSame($p->fingerprint(null),$p->fingerprint(json_encode($good)));
 }
 public function testPendingPurposeSessionChallengeLifetimeAndHashesAreStrict():void {
 $p=new PasskeyPending();foreach(['login','enroll'] as $purpose){$good=$this->pending($purpose);self::assertSame($good,$p->read(json_encode($good),1000));self::assertNotNull($p->read(json_encode($good),1299));self::assertNull($p->read(json_encode($good),999));self::assertNull($p->read(json_encode($good),1300));}
 $good=$this->pending();foreach([['purpose'=>'reset'],['user_id'=>4],['user_id'=>'0'],['session_hash'=>str_repeat('a',64)],['challenge'=>Base64Url::encode(random_bytes(31))],['ticket_hash'=>'x'],['binding_hash'=>[]],['policy_revision'=>str_repeat('z',32)],['context_revision'=>''],['created_at'=>0],['expires_at'=>1301],['expires_at'=>'1300']] as $change)self::assertNull($p->read(json_encode(array_replace($good,$change)),1000));self::assertNull($p->read(json_encode($good+['raw_cookie'=>'forbidden']),1000));self::assertNull($p->read(str_repeat('a',4097),1000));self::assertNull($p->read(json_encode(array_replace($this->pending('enroll'),['session_hash'=>''])),1000));
 }
 public function testCredentialBindsPublicMaterialOriginUserAndExactRevision():void {
 $p=new PasskeyCredential();$good=$this->credential();self::assertSame($good,$p->read(json_encode($good),1000));self::assertNull($p->read(json_encode($good),999));self::assertNotNull($p->read(json_encode(array_replace($good,['last_used_at'=>1100])),1100));
 foreach([['user_id'=>0],['user_id'=>'4'],['credential_id'=>''],['credential_id'=>Base64Url::encode(random_bytes(1025))],['user_handle'=>Base64Url::encode(random_bytes(31))],['public_key'=>'bad key'],['origin'=>'http://example.com:8443'],['origin'=>'https://example.com:8443/path'],['rp_id'=>'evil.com'],['context_revision'=>str_repeat('b',64)],['counter'=>-1],['counter'=>4294967296],['counter'=>'0'],['backup_eligible'=>0],['backup_eligible'=>false,'backed_up'=>true],['label'=>str_repeat('a',81)],['label'=>"bad\nlabel"],['created_at'=>1001],['last_used_at'=>1001],['last_used_at'=>999],['revision'=>'bad']] as $change)self::assertNull($p->read(json_encode(array_replace($good,$change),JSON_INVALID_UTF8_SUBSTITUTE),1000));
 self::assertNull($p->read(str_replace('Laptop',"\xff",json_encode($good)),1000));self::assertNull($p->read(json_encode($good+['private_key'=>'forbidden']),1000));self::assertNull($p->read(str_repeat('a',8193),1000));
 }
}
