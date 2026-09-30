<?php
namespace AmazingPlugins\Security\Tests\Unit\Passkeys;
use PHPUnit\Framework\TestCase;
use AmazingPlugins\Security\Passkeys\{PasskeyRepository,PasskeyContext,Base64Url};
final class RepositoryTest extends TestCase {
 private function pending():array {return ['version'=>1,'purpose'=>'login','user_id'=>0,'session_hash'=>'','account_revision'=>'','challenge'=>Base64Url::encode(random_bytes(32)),'ticket_hash'=>str_repeat('b',64),'binding_hash'=>str_repeat('c',64),'policy_revision'=>str_repeat('a',32),'context_revision'=>PasskeyContext::fromSiteUrl('https://example.com')->fingerprint(),'created_at'=>1000,'expires_at'=>1300];}
 public function testPendingAdmissionUsesFreshEnabledPolicyAndHardBudgets():void {
 foreach([['lock'=>'0'],['total'=>1000],['minute'=>100],['countInvalid'=>true],['queryResult'=>0],['policy'=>'corrupt'],['error'=>'unavailable']] as $change){$db=new PasskeyDb();foreach($change as $k=>$v)$db->$k=$v;self::assertFalse((new PasskeyRepository($db))->addPending($this->pending(),PasskeyContext::fromSiteUrl('https://example.com'),1000));self::assertFalse($db->suppressed);}
 $db=new PasskeyDb();self::assertTrue((new PasskeyRepository($db))->addPending($this->pending(),PasskeyContext::fromSiteUrl('https://example.com'),1000));self::assertTrue($db->released);self::assertStringContainsString('BINARY option_value=BINARY',$db->queries[0]);self::assertStringContainsString('INSERT INTO wp_amsec_passkey_pending',$db->queries[0]);
 $db=new PasskeyDb();$db->policy=json_encode(['version'=>1,'enabled'=>false,'revision'=>str_repeat('a',32)]);self::assertFalse((new PasskeyRepository($db))->addPending($this->pending(),PasskeyContext::fromSiteUrl('https://example.com'),1000));
 }
 public function testPendingClaimChecksBrowserPurposeContextAndAtomicallyConsumes():void {
 $ticket=random_bytes(32);$binding=random_bytes(32);$record=$this->pending();$record['ticket_hash']=hash('sha256',$ticket);$record['binding_hash']=hash('sha256',$binding);$raw=json_encode($record);$ctx=PasskeyContext::fromSiteUrl('https://example.com');
 foreach([[random_bytes(32),'login',$ctx,0,'',1000],[$binding,'enroll',$ctx,0,'',1000],[$binding,'login',PasskeyContext::fromSiteUrl('https://example.com:8443'),0,'',1000],[$binding,'login',$ctx,4,'',1000],[$binding,'login',$ctx,0,'',1300]] as $args){$db=new PasskeyDb();$db->rows=[['ticket_hash'=>$record['ticket_hash'],'record'=>$raw,'claimed_at'=>'0']];self::assertNull((new PasskeyRepository($db))->claim($ticket,...$args));self::assertSame([],$db->queries);}
 $db=new PasskeyDb();$db->rows=[['ticket_hash'=>$record['ticket_hash'],'record'=>$raw,'claimed_at'=>'0']];$repo=new PasskeyRepository($db);self::assertSame($record,$repo->claim($ticket,$binding,'login',$ctx,0,'',1000));self::assertStringContainsString('UPDATE wp_amsec_passkey_pending',$db->queries[0]);self::assertStringContainsString('p.claimed_at=0',$db->queries[0]);self::assertStringContainsString('BINARY option_value=BINARY',$db->queries[0]);$db->queryResult=0;self::assertNull($repo->claim($ticket,$binding,'login',$ctx,0,'',1000));
 }
 private function credential():array {
 $old=getenv('RANDFILE');$tmp=tempnam(sys_get_temp_dir(),'amsec-rand-');chmod($tmp,0600);putenv('RANDFILE='.$tmp);
 try {$private=openssl_pkey_new(['private_key_type'=>OPENSSL_KEYTYPE_EC,'curve_name'=>'prime256v1']);$public=openssl_pkey_get_details($private)['key'];}finally{putenv($old===false?'RANDFILE':'RANDFILE='.$old);unlink($tmp);}
 return ['version'=>1,'user_id'=>4,'credential_id'=>Base64Url::encode(random_bytes(32)),'user_handle'=>Base64Url::encode(random_bytes(32)),'public_key'=>$public,'origin'=>'https://example.com','rp_id'=>'example.com','context_revision'=>PasskeyContext::fromSiteUrl('https://example.com')->fingerprint(),'counter'=>0,'backup_eligible'=>true,'backed_up'=>false,'label'=>'Laptop','created_at'=>1000,'last_used_at'=>0,'revision'=>str_repeat('b',32)];
 }
 public function testCredentialAdmissionRejectsGlobalOwnQuotaWrongContextAndDisabledRevision():void {
 $record=$this->credential();$ctx=PasskeyContext::fromSiteUrl('https://example.com');
 foreach([['total'=>10000],['userCount'=>5],['lock'=>'0'],['queryResult'=>0],['policy'=>'corrupt'],['error'=>'missing']] as $change){$db=new PasskeyDb();foreach($change as $k=>$v)$db->$k=$v;self::assertFalse((new PasskeyRepository($db))->addCredential($record,$ctx,str_repeat('a',32),1000));}
 $db=new PasskeyDb();$r=new PasskeyRepository($db);self::assertTrue($r->addCredential($record,$ctx,str_repeat('a',32),1000));self::assertTrue($db->released);self::assertStringContainsString('BINARY option_value=BINARY',$db->queries[0]);self::assertFalse($r->addCredential($record,PasskeyContext::fromSiteUrl('https://example.com:8443'),str_repeat('a',32),1000));self::assertFalse($r->addCredential($record,$ctx,str_repeat('c',32),1000));
 }
 public function testLookupVerifiesIndexedMetadataAndConsumeUsesExactRawCasWithFreshPolicy():void {
 $record=$this->credential();$raw=json_encode($record);$hash=hash('sha256',Base64Url::decode($record['credential_id'],1024));$row=['id'=>$hash,'user_id'=>'4','record'=>$raw];$db=new PasskeyDb();$db->rows=[$row];$r=new PasskeyRepository($db);$ctx=PasskeyContext::fromSiteUrl('https://example.com');$id=Base64Url::decode($record['credential_id'],1024);$loaded=$r->credential($id,1000);self::assertSame(['id'=>$hash,'raw'=>$raw,'record'=>$record],$loaded);
 self::assertTrue($r->consumeCredential($loaded,0,true,$ctx,str_repeat('a',32),1000));self::assertStringContainsString('BINARY c.record=BINARY',$db->queries[0]);self::assertStringContainsString('BINARY option_value=BINARY',$db->queries[0]);self::assertStringContainsString('UPDATE wp_amsec_passkey_credentials',$db->queries[0]);
 $db->queryResult=0;self::assertFalse($r->consumeCredential($loaded,0,false,$ctx,str_repeat('a',32),1000));$db->queryResult=1;$db->policy='bad';self::assertFalse($r->consumeCredential($loaded,0,false,$ctx,str_repeat('a',32),1000));
 foreach([array_replace($row,['user_id'=>'5']),array_replace($row,['id'=>str_repeat('0',64)]),array_replace($row,['record'=>'bad'])] as $bad){$db->rows=[$bad];self::assertNull($r->credential($id,1000));}
 $db->rows=[$row,$row];self::assertNull($r->credential($id,1000));self::assertNull($r->credential(str_repeat('x',1025),1000));
 }
 public function testCredentialConsumeRefusesCounterRollbackOrEligibilityChangeAndOwnRemovalDoesNotCrossAccounts():void {
 $record=$this->credential();$record['counter']=2;$record['backup_eligible']=false;$raw=json_encode($record);$hash=hash('sha256',Base64Url::decode($record['credential_id'],1024));$loaded=['id'=>$hash,'raw'=>$raw,'record'=>$record];$db=new PasskeyDb();$r=new PasskeyRepository($db);$ctx=PasskeyContext::fromSiteUrl('https://example.com');
 foreach([[0,false],[2,false],[3,true]] as [$counter,$backup])self::assertFalse($r->consumeCredential($loaded,$counter,$backup,$ctx,str_repeat('a',32),1000));self::assertTrue($r->consumeCredential($loaded,3,false,$ctx,str_repeat('a',32),1000));self::assertTrue($r->removeOwn($hash,4));self::assertStringContainsString('user_id=4',end($db->queries));self::assertFalse($r->removeOwn('bad',4));self::assertFalse($r->removeOwn($hash,0));
 }
 public function testCleanupAndOwnRevocationAreBoundedAndStorageFailureDoesNotLookSuccessful():void {
 $db=new PasskeyDb();$repo=new PasskeyRepository($db);self::assertTrue($repo->cleanup(1000));self::assertStringContainsString('LIMIT 100',$db->queries[0]);self::assertTrue($repo->revokeUser(4));self::assertStringContainsString('user_id=4',implode(' ',$db->queries));self::assertFalse($repo->revokeUser(0));$db->error='failed';self::assertFalse($repo->cleanup(1000));self::assertFalse($repo->revokeUser(4));
 }
}
final class PasskeyDb {
 public string $prefix='wp_';public string $options='wp_options';public string $last_error='';public string $error='';public string $lock='1';public int $total=0;public int $minute=0;public int $userCount=0;public bool $countInvalid=false;public bool $suppressed=false;public bool $released=false;public int|false $queryResult=1;public array $queries=[];public array $rows=[];public string $policy='{"version":1,"enabled":true,"revision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}';
 public function prepare(string $sql,mixed ...$args):string {foreach($args as $a)$sql=preg_replace_callback('/%[sd]/',fn()=>is_int($a)?(string)$a:"'".str_replace("'","''",(string)$a)."'",$sql,1);return $sql;}
 public function suppress_errors(bool $value):bool {$old=$this->suppressed;$this->suppressed=$value;return $old;}
 public function get_var(string $sql):mixed {$this->last_error=$this->error;if(str_contains($sql,'RELEASE_LOCK')){$this->released=true;return '1';}if(str_contains($sql,'GET_LOCK'))return $this->lock;if(str_contains($sql,'SELECT option_value'))return $this->policy;if($this->countInvalid)return null;if(str_contains($sql,'created_at >='))return $this->minute;if(str_contains($sql,'user_id='))return $this->userCount;return $this->total;}
 public function get_results(string $sql,string $format):?array {$this->last_error=$this->error;return $this->error===''?$this->rows:null;}
 public function query(string $sql):int|false {$this->last_error=$this->error;$this->queries[]=$sql;return $this->error===''?$this->queryResult:false;}
}
