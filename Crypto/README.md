# CTF-Crypher

- [CTF-Crypher](#CTF-Crypher)
    - [MD5](#MD5)
    - [摩斯电码](#摩斯电码)
    - [brainfuck](#brainfuck)
    - [Ook](#Ook)
    - [Serpent](#Serpent)
    - [核心价值观编码](#核心价值观编码)
    - [盲文加密解密](#盲文加密解密)
    - [福尔摩斯-跳舞的小人](#福尔摩斯-跳舞的小人)
    - [音符加密解密](#音符加密解密)
    - [敲击码](#敲击码)
    - [凯撒加密解密](#凯撒加密解密)
    - [维吉尼亚密码](#维吉尼亚密码)
    - [栅栏密码加密解密](#栅栏密码加密解密)
    - [base64](#base64)
    - [base32](#base32)
    - [颜文字加密解密](#颜文字加密解密)
    - [rot13加密解密](#rot13加密解密)
    - [中文电码表](#中文电码表)
    - [五笔编码](#五笔编码)
    - [时间戳](#时间戳)
    - [手机键盘密码](#手机键盘密码)
    - [DES加密解密](#DES加密解密)
    - [Rabbit解密](Rabbit解密)
    - [Quoted-printable编码](#Quoted-printable编码)


## md5

https://www.somd5.com/

https://www.cmd5.com/


## 摩斯电码

.. .-.. --- ...- . -.-- --- ..-

https://www.ip138.com/mosi/

![](./img/mosi.png)

## brainfuck

 +++++++++++++++++.>

漏洞利用工具：Python-Brainfuck-master

python brainfuck.py 1.txt

![image](./img/brainfuck.png)

## Ook

在线解密网站：https://www.splitbrain.org/services/ook

## Serpent

蛇 snake 需要密钥

http://serpent.online-domain-tools.com/

## 核心价值观编码

社会主义核心价值观：富强、民主、文明、和谐；自由、平等、公正、法治；爱国、敬业、诚信、友善

http://ctf.ssleye.com/cvencode.html

https://wtool.com.cn/cvencode.html


## 盲文加密解密

https://www.qqxiuzi.cn/bianma/wenbenjiami.php?s=mangwen

## 福尔摩斯-跳舞的小人

![image](./img/tiaowuxiaoren.png)

## 音符加密解密

https://www.qqxiuzi.cn/bianma/wenbenjiami.php?s=yinyue

## 敲击码

  1  2  3  4  5
1 A  B C/K D  E
2 F  G  H  I  J
3 L  M  N  O  P
4 Q  R  S  T  U
5 V  W  X  Y  Z

..... ../... ./... ./... ../
  5,2     3,1    3,1    3,2
   W       L      L      M

## 凯撒加密解密

![](./img/kaisa.png)

26个字母位移密码

https://www.qqxiuzi.cn/bianma/kaisamima.php

## 变异凯撒

常规的凯撒密码是对每个字母做相同单位的移位。变异凯撒每个字母的移位可能各不相同。

往往是ASCII的移位密码，将密码转为如flag{}等格式，寻找规律

```py
c = "afZ_r9VYfScOeO_UL^RWUc"
move = 5

flag = ""
for i in c:
    flag += chr(ord(i)+ move)
    move = move +1

print(flag)
```


## 维吉尼亚密码

维吉尼亚密码是在凯撒密码基础上产生的一种加密方法，它将凯撒密码的全部25种位移排序为一张表，与原字母序列共同组成26行及26列的字母表。另外，维吉尼亚密码必须有一个密钥，这个密钥由字母组成，最少一个，最多可与明文字母数量相等。

https://www.qqxiuzi.cn/bianma/weijiniyamima.php

需要密钥

## 栅栏密码加密解密

栅栏密码是一种简单的移动字符位置的加密方法，规则简单，容易破解。栅栏密码的加密方式：把文本按照一定的字数分成多个组，取每组第一个字连起来得到密文1，再取每组第二个字连起来得到密文2……最后把密文1、密文2……连成整段密文。

明文：栅栏密码加密规则示例
每组字数：5

按照字数先把明文分成：
栅栏密码加
密规则示例

先取每组第一个字：栅密
再取每组第二个字：栏规
……

最后得到“栅密栏规密则码示加例”。


在线网站：
https://www.qqxiuzi.cn/bianma/zhalanmima.php

http://www.metools.info/code/fence154.html
## base64

https://base64.us/
## base32

base32和base64原理是一样的，32和64分别是`2^5`和`2^6`。
拿base32举例来说，每一个字符是有5Bit，但是ASCII字符有8Bit，所以base32是用8个base32字符来代替5个ASCII字符。


ToolsFx-1.8.0-jdk11 离线工具

https://www.qqxiuzi.cn/bianma/base.php 在线工具

## 颜文字加密解密

```
ﾟωﾟﾉ= /｀ｍ´）ﾉ ~┻━┻   //*´∇｀*/ ['_']; o=(ﾟｰﾟ)  =_=3; c=(ﾟΘﾟ) =(ﾟｰﾟ)-(ﾟｰﾟ); (ﾟДﾟ) =(ﾟΘﾟ)= (o^_^o)/ (o^_^o);(ﾟДﾟ)={ﾟΘﾟ: '_' ,ﾟωﾟﾉ : ((ﾟωﾟﾉ==3) +'_') [ﾟΘﾟ] ,ﾟｰﾟﾉ :(ﾟωﾟﾉ+ '_')[o^_^o -(ﾟΘﾟ)] ,ﾟДﾟﾉ:((ﾟｰﾟ==3) +'_')[ﾟｰﾟ] }; (ﾟДﾟ) [ﾟΘﾟ] =((ﾟωﾟﾉ==3) +'_') [c^_^o];(ﾟДﾟ) ['c'] = ((ﾟДﾟ)+'_') [ (ﾟｰﾟ)+(ﾟｰﾟ)-(ﾟΘﾟ) ];(ﾟДﾟ) ['o'] = ((ﾟДﾟ)+'_') [ﾟΘﾟ];(ﾟoﾟ)=(ﾟДﾟ) ['c']+(ﾟДﾟ) ['o']+(ﾟωﾟﾉ +'_')[ﾟΘﾟ]+ ((ﾟωﾟﾉ==3) +'_') [ﾟｰﾟ] + ((ﾟДﾟ) +'_') [(ﾟｰﾟ)+(ﾟｰﾟ)]+ ((ﾟｰﾟ==3) +'_') [ﾟΘﾟ]+((ﾟｰﾟ==3) +'_') [(ﾟｰﾟ) - (ﾟΘﾟ)]+(ﾟДﾟ) ['c']+((ﾟДﾟ)+'_') [(ﾟｰﾟ)+(ﾟｰﾟ)]+ (ﾟДﾟ) ['o']+((ﾟｰﾟ==3) +'_') [ﾟΘﾟ];(ﾟДﾟ) ['_'] =(o^_^o) [ﾟoﾟ] [ﾟoﾟ];(ﾟεﾟ)=((ﾟｰﾟ==3) +'_') [ﾟΘﾟ]+ (ﾟДﾟ) .ﾟДﾟﾉ+((ﾟДﾟ)+'_') [(ﾟｰﾟ) + (ﾟｰﾟ)]+((ﾟｰﾟ==3) +'_') [o^_^o -ﾟΘﾟ]+((ﾟｰﾟ==3) +'_') [ﾟ
```

http://www.atoolbox.net/Tool.php?Id=703

## rot13加密解密

http://www.mxcz.net/tools/rot13.aspx

http://www.ab126.com/goju/10818.html

https://rot13.com/

## 中文电码表

例子：ren
壬1103 仁0088 人0086 忍1804 韧7282 任0117 认6126 刃0432
妊1175 纫4771
https://gjy.bift.edu.cn/tzgg/22776.htm

## 五笔编码

例子：bnhn s wwy vffg vffg rrhy fhnv

https://www.qqxiuzi.cn/bianma/wubi.php

## 时间戳

https://tool.chinaz.com/tools/unixtime.aspx

## 手机键盘密码

999*666*88*2*777*33*6*999*4*4444*777*555*333*777*444*33*66*3*7777

![](./img/shoujimima.png)

## DES加密解密

也可能是3DES

https://www.sojson.com/encrypt_triple_des.html

DES密文开头都是`U2FsdGVkX1`,解密需要密钥

## Rabbit解密

在线网站
https://www.sojson.com/encrypt_rabbit.html
## Quoted-printable编码

Quoted-printable可译为“可打印字符引用编码”，Quoted-printable将任何8-bit字节值可编码为3个字符：一个等号"=“后跟随两个十六进制数字(0–9或A–F)表示该字节的数值。例如，ASCII码换页符（十进制值为12）可以表示为”=0C"，

在线解密网站：
http://www.mxcz.net/tools/QuotedPrintable.aspx

