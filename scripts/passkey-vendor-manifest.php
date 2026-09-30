<?php
/** Check the reviewed runtime dependency before making a release archive. */
declare(strict_types=1);
$root=dirname(__DIR__).'/src/Vendor/WebAuthn';
try {
 $manifest=json_decode(file_get_contents($root.'/manifest.json'),true,16,JSON_THROW_ON_ERROR);
 if (($manifest['package']??null)!=='lbuchs/WebAuthn'||($manifest['version']??null)!=='2.2.0'||($manifest['commit']??null)!=='20adb4a240c3997bd8cac7dc4dde38ab0bea0ed1'||($manifest['license']??null)!=='MIT'||count($manifest['files']??[])!==14)throw new RuntimeException('Unexpected dependency pin.');
 if(hash_file('sha256',$root.'/LICENSE')!==$manifest['license_sha256'])throw new RuntimeException('License hash mismatch.');
 $expected=['LICENSE','manifest.json'];
 foreach($manifest['files'] as $entry){
  $relative=$entry['path']??'';
  if(!is_string($relative)||preg_match('~^(?:[A-Za-z]+/)*[A-Za-z][A-Za-z0-9]*\.php$~D',$relative)!==1||in_array($relative,$expected,true)||!is_string($entry['upstream_sha256']??null)||preg_match('/^[a-f0-9]{64}$/D',$entry['upstream_sha256'])!==1)throw new RuntimeException('Invalid dependency manifest path/hash.');
  if(!is_file($root.'/'.$relative)||hash_file('sha256',$root.'/'.$relative)!==($entry['bundled_sha256']??null))throw new RuntimeException('Bundled dependency hash mismatch.');
  $expected[]=$relative;
 }
 $actual=[];
 foreach(new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root,FilesystemIterator::SKIP_DOTS)) as $file){if(!$file->isFile()||$file->isLink())throw new RuntimeException('Unexpected dependency entry.');$actual[]=substr($file->getPathname(),strlen($root)+1);}
 sort($expected);sort($actual);if($expected!==$actual)throw new RuntimeException('Unexpected dependency file set.');
 echo "Pinned WebAuthn runtime hashes and MIT license match. Independent audit remains a release gate.\n";
} catch(Throwable $error){fwrite(STDERR,"Passkey dependency check failed: ".$error->getMessage()."\n");exit(1);}
