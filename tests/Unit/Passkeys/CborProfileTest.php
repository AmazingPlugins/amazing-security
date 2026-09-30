<?php
namespace AmazingPlugins\Security\Tests\Unit\Passkeys;
use PHPUnit\Framework\TestCase;
use AmazingPlugins\Security\Passkeys\{BoundedCbor,AuthenticatorProfile};
final class CborProfileTest extends TestCase {
 public function testTypedDefiniteCborKeepsBytesSeparateFromTextAndBoundsPrefix():void {
 $p=new BoundedCbor();self::assertSame(['type'=>'bytes','value'=>'abc'],$p->read("\x43abc")['node']);self::assertSame(['type'=>'text','value'=>'abc'],$p->read("\x63abc")['node']);self::assertSame(-7,$p->read("\x26")['node']['value']);self::assertNull($p->read("\x01\x02"));self::assertSame(1,$p->read("\x01\x02",0,false)['consumed']);self::assertNull($p->read("\x63\xff\xff\xff"));
 }
 public function testDeepHugeIndefiniteTaggedFloatDuplicateOrTruncatedCborIsRefused():void {
 $p=new BoundedCbor();foreach([str_repeat("\x81",9)."\x01","\x9f\x01\xff","\xc0\x01","\xfa\x00\x00\x00\x00","\xa2\x61a\x01\x61a\x02","\x59\xff\xffa","\x58\x02a","\x1b".str_repeat("\xff",8),"\x99\x01\x00".str_repeat("\x01",256),str_repeat('x',32769)] as $bytes)self::assertNull($p->read($bytes));self::assertNotNull($p->read(str_repeat("\x81",8)."\x01"));
 }
 private function cose(int $algorithm=-7,int $curve=1,int $xLength=32):string {return "\xa5\x01\x02\x03".($algorithm===-7?"\x26":"\x25")."\x20".chr($curve)."\x21\x58".chr($xLength).str_repeat('x',$xLength)."\x22\x58\x20".str_repeat('y',32);}
 private function auth(string $id,int $flags=0x45,?string $cose=null):string {return hash('sha256','example.com',true).chr($flags).pack('N',3).str_repeat("\x00",16).pack('n',strlen($id)).$id.($cose??$this->cose());}
 private function attestation(string $auth,string $format='none'):string {return "\xa3\x63fmt".chr(0x60+strlen($format)).$format."\x67attStmt\xa0\x68authData\x59".pack('n',strlen($auth)).$auth;}
 public function testNoneEs256RegistrationBindsDeclaredIdAndRequiredFlags():void {
 $id=random_bytes(32);$p=new AuthenticatorProfile();$data=$this->auth($id);$r=$p->registration($this->attestation($data),$id);self::assertSame($data,$r['authenticator_data']);self::assertSame(3,$r['counter']);self::assertFalse($r['backup_eligible']);self::assertNull($p->registration($this->attestation($data),random_bytes(32)));self::assertNull($p->registration($this->attestation($data,'packed'),$id));
 foreach([0x44,0x41,0x05,0xc5,0x55,0x47,0x65] as $flags)self::assertNull($p->registration($this->attestation($this->auth($id,$flags)),$id));self::assertNotNull($p->registration($this->attestation($this->auth($id,0x5d)),$id));
 }
 public function testRegistrationRefusesUnsupportedAlgorithmCurveLengthsTrailingAndCredentialBudget():void {
 $p=new AuthenticatorProfile();$id=random_bytes(32);foreach([$this->cose(-6),$this->cose(-7,2),$this->cose(-7,1,31),$this->cose()."\x01",str_repeat("\x81",9)."\x01"] as $cose)self::assertNull($p->registration($this->attestation($this->auth($id,0x45,$cose)),$id));$huge=random_bytes(1025);self::assertNull($p->registration($this->attestation($this->auth($huge)),$huge));self::assertNull($p->registration($this->attestation('short'),$id));
 }
 public function testAssertionsAreExact37BytesUvPresentWithoutAttestationOrExtensions():void {
 $p=new AuthenticatorProfile();$good=hash('sha256','example.com',true)."\x05".pack('N',0);$r=$p->assertion($good);self::assertSame(0,$r['counter']);foreach([substr($good,0,36),$good.'extra',str_repeat('x',8193)] as $bad)self::assertNull($p->assertion($bad));foreach([0x01,0x04,0x45,0x85,0x15,0x07,0x25] as $flag)self::assertNull($p->assertion(substr($good,0,32).chr($flag).pack('N',1)));self::assertTrue($p->assertion(substr($good,0,32)."\x1d".pack('N',4294967295))['backed_up']);
 }
}
