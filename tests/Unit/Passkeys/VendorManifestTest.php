<?php
namespace AmazingPlugins\Security\Tests\Unit\Passkeys;
use PHPUnit\Framework\TestCase;
final class VendorManifestTest extends TestCase {
 public function testIsolatedVerifierLicenseHashesAndPackagingGateArePresent():void {
 $root=dirname(__DIR__,3);self::assertFileExists($root.'/scripts/passkey-vendor-manifest.php');$dir=$root.'/src/Vendor/WebAuthn';$manifest=json_decode(file_get_contents($dir.'/manifest.json'),true,16,JSON_THROW_ON_ERROR);self::assertSame('20adb4a240c3997bd8cac7dc4dde38ab0bea0ed1',$manifest['commit']);self::assertSame('MIT',$manifest['license']);self::assertSame($manifest['license_sha256'],hash_file('sha256',$dir.'/LICENSE'));self::assertCount(14,$manifest['files']);
 foreach($manifest['files'] as $entry){$path=$dir.'/'.$entry['path'];self::assertSame($entry['bundled_sha256'],hash_file('sha256',$path));self::assertStringNotContainsString('namespace lbuchs\\WebAuthn',file_get_contents($path));}
 self::assertStringContainsString('passkey-vendor-manifest.php',file_get_contents($root.'/scripts/package-preview.sh'));
 }
}
