<?php
namespace AmazingPlugins\Security\Tests\Unit\Digest;
use AmazingPlugins\Security\Integrity\OptionGateway;
final class MemoryOptions implements OptionGateway {
 public array $values=[]; public bool $failWrites=false; public bool $failStateWrites=false; public bool $failContentWrites=false;
 public function get(string $key):mixed{return $this->values[$key]??null;}
 public function add(string $key,string $value):bool{if($this->failWrites||($this->failStateWrites&&$key==='amsec_digest_state')||($this->failContentWrites&&$key==='amsec_content_state')||isset($this->values[$key]))return false;$this->values[$key]=$value;return true;}
 public function set(string $key,string $value):bool{if($this->failWrites)return false;$this->values[$key]=$value;return true;}
 public function delete(string $key):void{unset($this->values[$key]);}
 public function replaceIfSame(string $key,string $expected,string $replacement):bool{if($this->failWrites||($this->failStateWrites&&$key==='amsec_digest_state')||($this->failContentWrites&&$key==='amsec_content_state')||($this->values[$key]??null)!==$expected)return false;$this->values[$key]=$replacement;return true;}
 public function deleteIfSame(string $key,string $expected):bool{if($this->failWrites||($this->failStateWrites&&$key==='amsec_digest_state')||($this->failContentWrites&&$key==='amsec_content_state')||($this->values[$key]??null)!==$expected)return false;unset($this->values[$key]);return true;}
}
