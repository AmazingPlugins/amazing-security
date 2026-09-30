<?php
namespace AmazingPlugins\Security\Tests\Unit\Baseline;
use AmazingPlugins\Security\Baseline\ManifestBuilder;
use AmazingPlugins\Security\Baseline\BaselineManifest;
use PHPUnit\Framework\TestCase;
final class ManifestTest extends TestCase {
 public function test_add_modify_delete_differences_and_deterministic_fingerprint(): void {
  $a=new BaselineManifest(['a.php'=>str_repeat('a',64),'b.js'=>str_repeat('b',64)]);
  $b=new BaselineManifest(['a.php'=>str_repeat('c',64),'c.css'=>str_repeat('d',64)]);
  self::assertSame(['added'=>['c.css'],'modified'=>['a.php'],'deleted'=>['b.js']],$a->compare($b));
  self::assertSame($a->fingerprint(),(new BaselineManifest(['b.js'=>str_repeat('b',64),'a.php'=>str_repeat('a',64)]))->fingerprint());
 }
 public function test_complete_empty_current_reports_all_covered_files_deleted(): void {
  $reference=new BaselineManifest(['only.php'=>str_repeat('a',64)]);self::assertSame(['added'=>[],'modified'=>[],'deleted'=>['only.php']],$reference->compare(new BaselineManifest([])));
 }
 public function test_bounded_reader_collects_declared_source_assets_without_contents(): void {
  $dir=realpath(sys_get_temp_dir()).'/amsec-baseline-'.bin2hex(random_bytes(4));mkdir($dir,0700);file_put_contents($dir.'/fixture.php','<?php return 1;');file_put_contents($dir.'/readme.txt','Not declared source coverage');
  try{$m=(new ManifestBuilder())->collect($dir);self::assertSame(['fixture.php'=>hash('sha256','<?php return 1;')],$m->files);self::assertStringNotContainsString('<?php',json_encode($m->files));symlink($dir.'/fixture.php',$dir.'/link.php');$this->expectException(\RuntimeException::class);(new ManifestBuilder())->collect($dir);}finally{if(is_link($dir.'/link.php')){unlink($dir.'/link.php');}unlink($dir.'/fixture.php');unlink($dir.'/readme.txt');rmdir($dir);}
 }
 public function test_oversized_source_cannot_be_accepted_as_complete(): void {
  $dir=realpath(sys_get_temp_dir()).'/amsec-baseline-'.bin2hex(random_bytes(4));mkdir($dir,0700);file_put_contents($dir.'/large.php',str_repeat('x',2097153));
  try{$this->expectException(\RuntimeException::class);(new ManifestBuilder())->collect($dir);}finally{unlink($dir.'/large.php');rmdir($dir);}
 }
}
