<?php
if(!defined('WP_CLI')||!WP_CLI||DB_HOST!=='amsec-next-db'||!in_array(DB_NAME,['wordpress','wordpress69'],true)){exit(1);}
use AmazingPlugins\Security\Checks\FilesystemPermissionsCheck;
use AmazingPlugins\Security\Checks\UploadsExecutionCheck;
use AmazingPlugins\Security\Scan\ScanContext;
$dir=WP_CONTENT_DIR.'/amsec-mode-fixture-'.bin2hex(random_bytes(4));mkdir($dir,0700);$file=$dir.'/fixture.txt';file_put_contents($file,'Harmless mode fixture');$original=hash_file('sha256',$file);
try{
 foreach([[0600,'pass'],[0644,'warn'],[0666,'warn']] as [$mode,$expected]){chmod($file,$mode);$row=(new FilesystemPermissionsCheck(['configuration'=>$file]))->run(new ScanContext())[0];if($row->state!==$expected||str_contains(json_encode($row->toArray()),$dir)||$row->coverage!=='partial'){throw new RuntimeException('Mode interpretation/redaction failed.');}}
 chmod($dir,0777);$row=(new FilesystemPermissionsCheck(['uploads'=>$dir]))->run(new ScanContext())[0];if($row->state!=='warn'){throw new RuntimeException('World-writable directory missed.');}chmod($dir,0700);
 symlink($file,$dir.'/link');$row=(new FilesystemPermissionsCheck(['configuration'=>$dir.'/link']))->run(new ScanContext())[0];if($row->state!=='unknown'||$row->evidence['mode']!==null){throw new RuntimeException('Symlink accepted.');}
 $row=(new FilesystemPermissionsCheck(['configuration'=>$dir.'/absent']))->run(new ScanContext())[0];if($row->state!=='unknown'){throw new RuntimeException('Missing path passed.');}
 $row=(new UploadsExecutionCheck())->run(new ScanContext())[0];if($row->state!=='unknown'||$row->coverage!=='unavailable'){throw new RuntimeException('Execution coverage overstated.');}
 mkdir($dir.'/hidden',0700);mkdir($dir.'/hidden/uploads',0700);chmod($dir.'/hidden',0000);$hidden=static function($value)use($dir){$value['basedir']=$dir.'/hidden/uploads';$value['error']=false;return $value;};add_filter('upload_dir',$hidden);try{$paths=FilesystemPermissionsCheck::wordpressPaths();if(!array_key_exists('uploads',$paths)){throw new RuntimeException('Inaccessible uploads omitted.');}$rows=(new FilesystemPermissionsCheck($paths))->run(new ScanContext());$uploads=array_values(array_filter($rows,static fn($r)=>$r->evidence['location']==='uploads'));if(count($uploads)!==1||$uploads[0]->state!=='unknown'){throw new RuntimeException('Inaccessible uploads not unknown.');}}finally{remove_filter('upload_dir',$hidden);chmod($dir.'/hidden',0700);rmdir($dir.'/hidden/uploads');rmdir($dir.'/hidden');}
 $run=(new AmazingPlugins\Security\Scan\LocalHardeningScanService())->run();$ids=array_column(array_map(static fn($r)=>$r->toArray(),$run->results),'check_id');foreach(['filesystem-permissions','uploads-php-execution'] as $id){if(!in_array($id,$ids,true)){throw new RuntimeException('Hardening report omitted new check.');}}
 if(hash_file('sha256',$file)!==$original){throw new RuntimeException('Check changed fixture content.');}
 echo 'Permissions: real mode transitions, world-write/configuration-read warnings, unknown link/missing state, redaction, unchanged contents and saved hardening report passed.'.PHP_EOL;
}finally{if(is_link($dir.'/link')){unlink($dir.'/link');}unlink($file);chmod($dir,0700);rmdir($dir);}
