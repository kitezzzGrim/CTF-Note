# BUUCTF-MISC

- [BUUCTF-MISC](#BUUCTF-MISC)
    - [二维码扫描](#二维码扫描)
    - [Webshell](#Webshell)
    - [神秘龙卷风](#神秘龙卷风)
    - [面具下的flag](#面具下的flag)
    - [刷新过的图片](#刷新过的图片)
    - [[BJDCTF2020]认真你就输了](#[BJDCTF2020]认真你就输了)
    - [菜刀666](#菜刀666)
    - [[BJDCTF2020]藏藏藏](#[BJDCTF2020]藏藏藏)
    - [秘密文件](#秘密文件)
    - [你猜我是个啥](#你猜我是个啥)
    - [神奇的二维码](#神奇的二维码)
    - [鸡你太美](#鸡你太美)
    - [just_a_rar](#just_a_rar)
    - [穿越时空的思念](#穿越时空的思念)
    - [纳尼](#纳尼)
    - [outguess](#outguess)
    - [我有一只马里奥](#我有一只马里奥)
    - [谁赢了比赛？](#谁赢了比赛？)
    - [excel破解](#excel破解)
    - [gakki](#gakki)
    - [来题中等的吧](#来题中等的吧)
    - [base64隐写](base64隐写)
    - [find_me](#find_me)
    - [sqltest](#sqltest)
    - [伟大的侦探](#伟大的侦探)
    - [黑客帝国](#黑客帝国)
    - [你能看懂音符吗](#你能看懂音符吗)
    - [KO](#KO)
    - [你有没有好好看网课?](#你有没有好好看网课?)
    - [ezmisc](#ezmisc)
    - [喵喵喵](#喵喵喵)
    - [caesar](#caesar)
    - [低个头](#低个头)
    - [弱口令](#弱口令)
    - [john-in-the-middle](#john-in-the-middle)
    - [NTFS数据流](#NTFS数据流)
    - [我吃三明治](#我吃三明治)
    - [single_dog](#single_dog)
    - [SXMgdGhpcyBiYXNlPw==](#SXMgdGhpcyBiYXNlPw==)
    - [黄金6年](#黄金6年)
    - [zip](#zip)
    - [间谍启示录](#间谍启示录)
    - [swp](#swp)
    - [吹着贝斯扫二维码](#吹着贝斯扫二维码)
    - [小易的U盘](#小易的U盘)
    - [从娃娃抓起](#从娃娃抓起)
    - [alison_likes_jojo](#alison_likes_jojo)
    - [zips](#zips)
    - [百里挑一](#百里挑一)
    - [爬](#爬)
    - [Attack](#Attack)
    - [千层套路](#千层套路)
    - [girlfriend](#girlfriend)
    - [Game](#Game)
    - [docx](#docx)
    - [CyberPunk](#CyberPunk)
    - [followme](#followme)
    - [USB](#USB)
    - [通行证](#通行证)
    - [虚假的压缩包](#虚假的压缩包)
    - [Network](#Network)
    - [draw](#draw)
    - [明文攻击](#明文攻击)
    - [蜘蛛侠呀](#蜘蛛侠呀)
    - [UTCTF2020-file-header](#UTCTF2020-file-header)
    - [安洵杯-2019-easy-misc](#安洵杯-2019-easy-misc)
    - [MRCTF2020-Hello_misc](#MRCTF2020-Hello_misc)
    - [BSidesSF2019-zippy](#BSidesSF2019-zippy)
    - [MRCTF2020-不眠之夜](#MRCTF2020-不眠之夜)
## 二维码扫描

sudo apt install zbar-tools

## Webshell 后门

用D盾查杀找webshell

## 神秘龙卷风

下载来是rar压缩包,用archpr2爆破得到文本

内容为brainfuck，解密工具Python-Brainfuck-master得到flag

## 面具下的flag

用binwalk分离图片，得到一个压缩包：74DFE.zip,解压得flag.vmdk

linux下用7z解压vmdk文件

第一个文件明显brainfuck解密：flag{N7F5_AD5

第二个明显Ook解密 : _i5_funny!}

flag{N7F5_AD5_i5_funny!}

## 刷新过的图片

考点：F5隐写

利用F5-steganography利用工具

```java
java Extract Misc.jpg
```

查看output.txt发现开头有PK内容，说明是个ZIP文件头，修改后缀名解压得到flag

## snake.jpg

binwalk分离得到压缩包，里面有cipher和key两个文本，打开key  base64解密得到

`What is Nicki Minaj's favorite song that refers to snakes?`

搜索可得到密码为 anaconda

snake还有另外一个英文翻译：Serpent算法 解密即可

http://serpent.online-domain-tools.com/



## [BJDCTF2020]认真你就输了

binwalk发现flag

## 菜刀666

http.request.method==POST,追踪TCP流发现十六进制FF D8开头FF D9结尾，判断为jpg图片.


```py
import binascii
s = "十六进制内容"
with open('1.jpg','wb') as f:
    f.write(binascii.unhexlify(s))
```

得到一张带密码的图片。binwalk分离流量包得到zip，输入密码即可。

## [BJDCTF2020]藏藏藏

kali下foremost分离,得到压缩包，里面是二维码，识别得到flag

## 秘密文件

深夜里，Hack偷偷的潜入了某公司的内网，趁着深夜偷走了公司的秘密文件，公司的网络管理员通过通过监控工具成功的截取Hack入侵时数据流量，但是却无法分析出Hack到底偷走了什么机密文件，你能帮帮管理员分析出Hack到底偷走了什么机密文件吗？ 注意：得到的 flag 请包上 flag{} 提交

过滤FTP流追踪发现rar包，尝试foremost分解

![](./img/secret.png)

然后暴力破解即可。

## 你猜我是个啥

用010打开发现png头，修改后缀为png，发现二维码，扫描后说flag不在这,010查看查找flag发现在末尾

## 神奇的二维码

扫描后未发现flag，binwalk分离四个压缩包，其中有一个base64多次得到的密码是第四个压缩包的密码，音频隐写Audacity


文件->导出为wav

kali
```bash
morse2ascii good.wav
```

将`t`替换为`-`，e替换为`.`

flag{morseisveryveryeasy}

## 鸡你太美

比较两张图片，添加丢失的git头

## just_a_rar

archpr爆破即可，是一张图片，右键查看属性发现flag

## 穿越时空的思念

嫦娥当年奔月后，非常后悔，因为月宫太冷清，她想：早知道让后羿自己上来了，带了只兔子真是不理智。于是她就写了一首曲子，诉说的是怀念后羿在的日子。无数年后，小明听到了这首曲子，毅然决定冒充后羿。然而小明从曲子中听不出啥来，咋办。。（该题目为小写的32位字符，提交即可） 注意：得到的 flag 请包上 flag{} 提交

audacity需要先将两个声道分离，分离立体声到单声道，导出文件wav

用kali的morse2ascii得到32位字符

## 纳尼

添加GIF89

## outguess

右键查看图片属性发现 公正民主公正文明公正和谐
核心价值解码得到abc

outguess -k "abc" -r mmm.jpg hidden.txt

## 我有一只马里奥

下载后点击exe出现1.txt，内容为ntfs flag.txt

猜测是ntfs隐写，用NtfsStreamsEditor扫1.txt

## 谁赢了比赛？

binwalk得到压缩包，暴力破解即可

得到gif图片，stegsolve-frame browser 要是对GIF之类的动图进行分解，把动图一帧帧的放，有时候会是二维码

第310帧有一行文字，保存下来单独对其stegsolve red plane 0发现二维码，扫描得到flag

## excel破解

010打开搜索flag

## gakki

binwalk分离压缩包，爆破压缩包得到文本

```
# -*- coding:utf-8 -*-
#Author: mochu7
# 字频统计
alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()_+- =\\{\\}[]"
strings = open('./flag.txt').read()

result = {}
for i in alphabet:
	counts = strings.count(i) # 计算出现的次数
	i = '{0}'.format(i)
	result[i] = counts

res = sorted(result.items(),key=lambda item:item[1],reverse=True)  # 排序操作 True降序
for data in res:
	print(data)

for i in res:
	flag = str(i[0])
	print(flag[0],end="")
```

## 来题中等的吧

看图识别摩斯电码

.- .-.. .--. .... .- .-.. .- -...

## base64隐写

```py
# -*- coding: cp936 -*-

b64chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

with open('1.txt', 'rb') as f:
    bin_str = ''
    for line in f.readlines():
        stegb64 = ''.join(line.split()) # 读取文本每一行
        rowb64 =  ''.join(stegb64.decode('base64').encode('base64').split()) # 把内容编码成原生base64

        offset = abs(b64chars.index(stegb64.replace('=','')[-1])-b64chars.index(rowb64.replace('=','')[-1])) # 文本的base64 - 原生base64
        equalnum = stegb64.count('=') #no equalnum no offset
        if equalnum:
            bin_str += bin(offset)[2:].zfill(equalnum * 2)

        print ''.join([chr(int(bin_str[i:i + 8], 2)) for i in xrange(0, len(bin_str), 8)]) #8 位一组
```

## find_me

右键属性发现盲文 解密即可

https://www.qqxiuzi.cn/bianma/wenbenjiami.php?s=mangwen

## sqltest

文件-导出对象-HTTP

我们可以从中推断出正确的ascii值，在对一个字符进行bool判断时，被重复判断的ASCII值就是正确的字符，最后提取到：

```bash
tshark -r sqltest.pcapng -Y "http.request" -T fields -e http.request.full_uri > data.txt
```

https://www.cnblogs.com/yunqian2017/p/15124198.html


102 108 97 103 123 52 55 101 100 98 56 51 48 48 101 100 53 102 57 98 50 56 102 99 53 52 98 48 100 48 57 101 99 100 101 102 55 125

flag{47edb8300ed5f9b28fc54b0d09ecdef7}

## 伟大的侦探

压缩包密码:摂m墷m卪倕ⅲm仈Z
呜呜呜,我忘记了压缩包密码的编码了,大家帮我解一哈。

用010editor打开 EBCDIC编码得到压缩包密码

里面是跳舞的小人

福尔摩斯-跳舞的小人解密

iloveholmesandwllm

## 黑客帝国

Jack很喜欢看黑客帝国电影，一天他正在上网时突然发现屏幕不受控制，出现了很多数据再滚屏，结束后留下了一份神秘的数据文件，难道这是另一个世界给Jack留下的信息？聪明的你能帮Jack破解这份数据的意义吗？ 注意：得到的 flag 请包上 flag{} 提交

打开发现是十六进制文件 用010editor导入十六进制文件，发现rar开头文件，保存到本地为1.rar，暴力破解得到一张损坏的png图片，010查看发现是JFIF，这是jpg格式特征，修改文件头为jpg的得到图片

## 你能看懂音符吗

压缩包损坏，打开010editor 改成Rar文件头，里面有docx

呀！一不小心把文档里的东西弄没了……

010editor继续查看发现PK文件头，修改后缀为zip

在word的document.xml发现

♭♯♪‖¶♬♭♭♪♭‖‖♭♭♬‖♫♪‖♩♬‖♬♬♭♭♫‖♩♫‖♬♪♭♭♭‖¶∮‖‖‖‖♩♬‖♬♪‖♩♫♭♭♭♭♭§‖♩♩♭♭♫♭♭♭‖♬♭‖¶§♭♭♯‖♫∮‖♬¶‖¶∮‖♬♫‖♫♬‖♫♫§=

音符解密即可

## KO

OoK解密

## 你有没有好好看网课?

flag3 6位数字暴力破解得到文档和mp4

根据文档提示 用pr新建项目-导入mp4 在5.20和7.11发现信息

..... ../... ./... ./... ../
  5,2     3,1    3,1    3,2
   W       L      L      M
dXBfdXBfdXA=

wllmup_up_up 输入压缩包得到图片，010editor在末尾发现flag

## ezmisc

修改宽高 在第二行第6 7列  7是高

## 喵喵喵

stegsolve发现在红绿蓝 0位上方有不一样的东西，可以猜测是LSB隐写

![](./img/miao1.png)

保存为二进制文件，修改多余的文件头 再修改宽高 二维码扫描

https://pan.baidu.com/s/1pLT2J4f

NtfsStreamsEditor软件去提取隐藏文件。（这一步我一直提取失败，没搞懂为什么，后来发现下载的压缩包用WinRAR解压才可以提取到隐藏的文件，据大佬说流隐写得用WinRAR解压

最后得到pyc 反编译即可

```bash
#!/usr/bin/env python
# visit https://tool.lu/pyc/ for more information
import base64

def encode():
    flag = '*************'
    ciphertext = []
    for i in range(len(flag)):
        s = chr(i ^ ord(flag[i])) # flag每个字符转为十进制再与i异或 然后转为字符
        if i % 2 == 0:
            s = ord(s) + 10
        else:
            s = ord(s) - 10
        ciphertext.append(str(s))
    return ciphertext[::-1]

def decode():
    flag = ''
    ciphertext = [
        '96',
        '65',
        '93',
        '123',
        '91',
        '97',
        '22',
        '93',
        '70',
        '102',
        '94',
        '132',
        '46',
        '112',
        '64',
        '97',
        '88',
        '80',
        '82',
        '137',
        '90',
        '109',
        '99',
        '112']
    ciphertext = ciphertext[::-1]
    for i in range(len(ciphertext)):
        if i % 2 == 0:
            s = int(ciphertext[i]) - 10
        else:
            s = int(ciphertext[i]) + 10
        s = chr(i ^ s)
        flag +=  s
        print(flag)

if __name__ == '__main__':
    decode()
```

## caesar
题目：caesar

描述：gmbhjtdbftbs

flag格式：XXX 明文

提交：直接提交明文 （小写）

中文翻译是凯撒，解密皆可

## 低个头

题目：低个头

描述：EWAZX RTY TGB IJN IO KL 请破解该密文 f

lag格式：XXX 明文

提交：直接提交明文（大写）

键盘密码


flag{CTF}

## 弱口令

老菜鸡，伤了神，别灰心，莫放弃，试试弱口令 注意：得到的 flag 请包上 flag{} 提交

打开压缩包，有密码，右边可以发现看不见的密码，复制到新文本sublime 全选可看见摩斯密码

![](./img/ruokol.png)


.... . .-.. .-.. ----- ..-. --- .-. ..- --

摩斯电码解密得到压缩包密码，解压后是一张女神图片

LSB隐写

python2 lsb.py extract 女神.png 1.txt 123456

## john-in-the-middle

导出http对象文件
也可也foremost
 对logo.png进行stegsolve观察

## NTFS数据流

直接用ntfstreameditor2工具读取

## 我吃三明治

foremost分离两张图片

010打开原图对比 在拼接处发现base32 ，解密得到flag

## single_dog

颜文字解密

http://www.atoolbox.net/Tool.php?Id=703

## SXMgdGhpcyBiYXNlPw==

base64隐写

## 黄金6年

下载后是mp4文件，用010打开在末尾发现base64，解码后是rar文件，转二进制文本脚本如下：

```py
import base64

code = "UmFyIRoHAQAzkrXlCgEFBgAFAQGAgADh7ek5VQIDPLAABKEAIEvsUpGAAwAIZmxhZy50eHQwAQADDx43HyOdLMGWfCE9WEsBZprAJQoBSVlWkJNS9TP5du2kyJ275JzsNo29BnSZCgMC3h+UFV9p1QEfJkBPPR6MrYwXmsMCMz67DN/k5u1NYw9ga53a83/B/t2G9FkG/IITuR+9gIvr/LEdd1ZRAwUEAA=="

with open ('1.rar','wb') as f:
    f.write(base64.b64decode(code))
```

压缩包需要密码，在mp4里面二维码，需要分帧,一共4个二维码拼接压缩包密码。



## zip

拼在一起解下base64就有flag 注意：得到的 flag 请包上 flag{} 提交

很多压缩包，但是里面的内容非常小，小于5字节，可以尝试使用CRC32爆破得到其内容

```py
#coding:utf-8
import zipfile
import string
import binascii

def CrackCrc(crc):
    for i in dic:
        for j in dic:
            for p in dic:
                for q in dic:
                    s = i + j + p + q
                    if crc == (binascii.crc32(s) & 0xffffffff):
                        #print s
                        f.write(s)
                        return

def CrackZip():
    for I in range(68):
        file = 'out' + str(I) + '.zip'
        f = zipfile.ZipFile(file, 'r')
        GetCrc = f.getinfo('data.txt')
        crc = GetCrc.CRC
        #以上3行为获取压缩包CRC32值的步骤
        #print hex(crc)
        CrackCrc(crc)

dic = string.ascii_letters + string.digits + '+/='

f = open('out.txt', 'w')
CrackZip()
f.close()
```

base64转字节文件

z5BzAAANAAAAAAAAAKo+egCAIwBJAAAAVAAAAAKGNKv+a2MdSR0zAwABAAAAQ01UCRUUy91BT5UkSNPoj5hFEVFBRvefHSBCfG0ruGnKnygsMyj8SBaZHxsYHY84LEZ24cXtZ01y3k1K1YJ0vpK9HwqUzb6u9z8igEr3dCCQLQAdAAAAHQAAAAJi0efVT2MdSR0wCAAgAAAAZmxhZy50eHQAsDRpZmZpeCB0aGUgZmlsZSBhbmQgZ2V0IHRoZSBmbGFnxD17AEAHAA==

可以看到文件尾为07 00 是rar的文件尾，修补文件头526172211A0700

## 间谍启示录

在城际公路的小道上，罪犯G正在被警方追赶。警官X眼看他正要逃脱，于是不得已开枪击中了罪犯G。罪犯G情急之下将一个物体抛到了前方湍急的河流中，便头一歪突然倒地。警官X接近一看，目标服毒身亡。数分钟后，警方找到了罪犯遗失物体，是一个U盘，可惜警方只来得及复制镜像，U盘便报废了。警方现在拜托你在这个镜像中找到罪犯似乎想隐藏的秘密。 注意：得到的 flag 请包上 flag{} 提交

下载后是iso文件 用foremost分离

运行flag.exe得到flag

## swp

foremost分离pcag，有压缩包，可修复也可直接导出

## 吹着贝斯扫二维码

```py
#coding:utf-8
import os

path = "G:\\Github\\CTF-Note\\tools\\批量修改文件名后缀\\test"

for i in os.listdir(path):
    # print(i)
    if i == 'flag.zip':
        continue
    else:
        old_name = os.path.join(path,i)
        new_name = os.path.join(path,i + '.jpg')
        os.rename(old_name,new_name)
```

得到一堆二维码碎片。用ps拼接后扫描

BASE Family Bucket ???
85->64->85->13->16->32



压缩包注释如下：GNATOMJVIQZUKNJXGRCTGNRTGI3EMNZTGNBTKRJWGI2UIMRRGNBDEQZWGI3DKMSFGNCDMRJTII3TMNBQGM4TERRTGEZTOMRXGQYDGOBWGI2DCNBY

ThisIsSecret!233

## 小易的U盘

小易的U盘中了一个奇怪的病毒，电脑中莫名其妙会多出来东西。小易重装了系统，把U盘送到了攻防实验室，希望借各位的知识分析出里面有啥。请大家加油噢，不过他特别关照，千万别乱点他U盘中的资料，那是机密。 注意：得到的 flag 请包上 flag{} 提交

foremost分离iso

提示32exe有东西，打开寻找发现flag


## 从娃娃抓起
题目描述：伟人的一句话，标志着一个时代的开始。那句熟悉的话，改变了许多人的一生，为中国三十年来计算机产业发展铺垫了道路。两种不同的汉字编码分别代表了汉字信息化道路上的两座伟大里程碑。请将你得到的话转为md5提交，md5统一为32位小写。

0086 1562 2535 5174
bnhn s wwy vffg vffg rrhy fhnv

请将你得到的这句话转为md5提交，md5统一为32位小写。
提交格式：flag{md5}

中文电码和五笔编码

## alison_likes_jojo

题目描述：As we known, Alison is a pretty girl.

boki.jpg分离出一个zip，爆破出来密码是888866，得到一个文本多次base64解密后得到key：killerqueen

jljy.jpg是outguess隐写

outguess -k "killerqueen" -r jljy.jpg  hidden.txt

## zips

222.zip用ziperello爆破得到111.zip

111.zip有flag.zip和加密的setup.sh,先把flag.zip移出去，伪加密，可以用工具ZipCenOp.jar

打开setup.sh

```bash
#!/bin/bash
#
zip -e --password=`python -c "print(__import__('time').time())"` flag.zip flag

```

可以看到是时间戳
https://tool.chinaz.com/tools/unixtime.aspx

考虑到出题时间，前两位为15，15????????.?? 用archpr进行掩码爆破

flag{fkjabPqnLawhvuikfhgzyffj}

## (╯°□°）╯︵ ┻━┻

(╯°□°）╯︵ ┻━┻
50pt

(╯°□°）╯︵ ┻━┻

d4e8e1f4a0f7e1f3a0e6e1f3f4a1a0d4e8e5a0e6ece1e7a0e9f3baa0c4c4c3d4c6fbb9b2b2e1e2b9b9b7b4e1b4b7e3e4b3b2b2e3e6b4b3e2b5b0b6b1b0e6e1e5e1b5fd


```py
s = "d4e8e1f4a0f7e1f3a0e6e1f3f4a1a0d4e8e5a0e6ece1e7a0e9f3baa0c4c4c3d4c6fbb9b2b2e1e2b9b9b7b4e1b4b7e3e4b3b2b2e3e6b4b3e2b5b0b6b1b0e6e1e5e1b5fd"

str_s = ''
str_get = []

for j in range(129): # 循环测试所有数减掉1-128得到的ASCII码
    str_16 = ''
    for i in range(len(s)):
        if i % 2 ==0:
            str_s = s[i-2] + s[i-1]
            str_16 += chr(int(str_s,16)-j) # 十六进制转十进制
    print(str_16)


```

## 百里挑一

好多漂亮的壁纸，赶快挑一张吧！ 注意：得到的 flag 请包上 flag{} 提交

首先导出http对象

`exiftool * | grep flag` 发现一半flag

追踪TCP流在114处发现另一半flag 可以右下角点击流一个个翻阅特征exif

## 爬

010发现是pdf文件，修改后缀后，移动图片发现十六进制 解码得到flag

## Attack

foremost分离发现zip需要密码
wireshark导出http对象发现lsass.dmp

lsass是windows系统的一个进程，用于本地安全和登陆策略。mimikatz可以从 lsass.exe 里获取windows处于active状态账号明文密码。本题的lsass.dmp就是内存运行的镜像，也可以提取到账户密码

https://github.com/gentilkiwi/mimikatz/releases/

以管理员身份运行
```
privilege::debug
sekurlsa::minidump lsass.dmp
sekurlsa::logonpasswords full
```

 W3lc0meToD0g3

## 千层套路

打开文件，发现是个以数字命名的压缩包，解压密码恰好是那个数字，写个脚本跑一下

```py
import zipfile
name = '0573'
while True:
    fz = zipfile.ZipFile(name + '.zip', 'r')
    fz.extractall(pwd=bytes(name, 'utf-8'))
    name = fz.filelist[0].filename[0:4]
    fz.close()
```

```py
from PIL import Image

x = y = 200 # 需要手动将()去掉
img = Image.new("RGB",(x,y))
file = open('./qr.txt','r')

for width in range(0,x):
    for height in range(0,y):
        line = file.readline()
        rgb = line.split(',')
        img.putpixel((width,height),(int(rgb[0]),int(rgb[1]),int(rgb[2])))
img.save('flag.jpg')
```

需要手动将qr的()去掉

## girlfriend

听起来像是在打电话输入号码的声音，猜测DTMF拨号音识别，有个程序可以识别一下dtmf2num.exe

> dtmf2num.exe girlfriend.wav

999*666*88*2*777*33*6*999*4*4444*777*555*333*777*444*33*66*3*7777

手机键盘密码

999 ---> y666 ---> o88 ---> u2 ---> a777 ---> r33 ---> e6 ---> m999 ---> y4 ---> g4444 ---> i777 ---> r555 ---> l333 ---> f777 ---> r444 ---> i33 ---> e66 ---> n3 ---> d7777 ---> syouaremygirlfriends
flag{youaremygirlfriends}

## Game

先看源代码的index.html发现

 ON2WG5DGPNUECSDBNBQV6RTBNMZV6RRRMFTX2===


base32编码 suctf{hAHaha_Fak3_F1ag}

图片LSB分析得到加密的字符串


U2FsdGVkX1+zHjSBeYPtWQVSwXzcVFZLu6Qm0To/KeuHg8vKAxFrVQ==

因为U2FsdGVkX1开头可知道是DES加密

因为DES加密之后开头都是这几位，不过解密需要秘钥，就是前面的fake密钥

https://www.sojson.com/encrypt_triple_des.html

得到flag

## docx

binwalk 分离得到flag

## CyberPunk

更改系统时间即可

## followme

导出http对象，观察可知是个爆破密码，`grep -r 'CTF' ./output `

## USB

binwalk分离key.ftm,分离出usb流量包key.pcap

用UsbKeyboardDataHacker工具提取出流量，key值为xinan

010editor打开233.rar，根据分析rar文件头，具体可见misc/rar文件头，在第二行第六列发现7A应该是74，修改后多了一张图，stegolve在blue plane 0发现二维码，扫描后得到

ci{v3erf_0tygidv2_fc0}

维吉尼亚密码解密得到 fa{i3eei_0llgvgn2_sc0}

栅栏解密2得到flag

## 通行证

a2FuYmJyZ2doamx7emJfX19ffXZ0bGFsbg==

套娃题目

base64解密-栅栏密码 密钥7 - 凯撒密码

## 虚假的压缩包

```
数学题
n = 33
e = 3
解26

-------------------------
答案是
```

明显的rsa题

```py
import gmpy2

## 已知 p q e c 求 m
p = 3
q = 11
e = 3
c = 26
n = 33
s = (p- 1) * (q - 1)
d = gmpy2.invert(e,s)
m = pow(c,d,n)

print(pow(c, d, n))
```

压缩包密码：答案是5

得到图片和文件 图片改长宽发现要求异或5，写脚本

```py
original = open("亦真亦假",'r').read()
flag = open("flag",'w')
for i in original:
    tmp = int(i,16)^5
    flag.write(hex(tmp)[2:])
```
用notepad++右上角插件
hex->Ascii

后缀doc，全选换成蓝色发现flag


flag{_th2_7ru8_2iP_}

## Network

TTL隐写-得到压缩包-伪加密得到一堆base64字符，写脚本批量跑到底

flag{189ff9e5b743ae95f940a6ccc6dbd9ab}

## draw

```
cs pu lt 90 fd 500 rt 90 pd fd 100 rt 90 repeat 18[fd 5 rt 10] lt 135 fd 50 lt 135 pu bk 100 pd setcolor pick [ red orange yellow green blue violet ] repeat 18[fd 5 rt 10] rt 90 fd 60 rt 90 bk 30 rt 90 fd 60 pu lt 90 fd 100 pd rt 90 fd 50 bk 50 setcolor pick [ red orange yellow green blue violet ] lt 90 fd 50 rt 90 fd 50 pu fd 50 pd fd 25 bk 50 fd 25 rt 90 fd 50 pu setcolor pick [ red orange yellow green blue violet ] fd 100 rt 90 fd 30 rt 45 pd fd 50 bk 50 rt 90 fd 50 bk 100 fd 50 rt 45 pu fd 50 lt 90 pd fd 50 bk 50 rt 90 setcolor pick [ red orange yellow green blue violet ] fd 50 pu lt 90 fd 100 pd fd 50 rt 90 fd 25 bk 25 lt 90 bk 25 rt 90 fd 25 setcolor pick [ red orange yellow green blue violet ] pu fd 25 lt 90 bk 30 pd rt 90 fd 25 pu fd 25 lt 90 pd fd 50 bk 25 rt 90 fd 25 lt 90 fd 25 bk 50 pu bk 100 lt 90 setcolor pick [ red orange yellow green blue violet ] fd 100 pd rt 90 arc 360 20 pu rt 90 fd 50 pd arc 360 15 pu fd 15 setcolor pick [ red orange yellow green blue violet ] lt 90 pd bk 50 lt 90 fd 25 pu home bk 100 lt 90 fd 100 pd arc 360 20 pu home
```

logo语言

https://www.calormen.com/jslogo/

flag{RCTF_HeyLogo}

## 明文攻击

binwalk woojpg发现有zip，无法分离出来，需要手动添加zip文件头
504B0304

在0304前添加文件头504B

打开后得到this is the flag.

发现题给的压缩包里面有一个flag.txt，和刚解压出的txt大小相同，明文攻击

点击确定保存为zip文件，解压出现flag

## 蜘蛛侠呀

所有的icmp包后面都跟了一串数据，使用tshark把这些全部提取出来

`tshark -r out.pcap -T fields -e data > data.txt`

脚本去重-> 十六进制数据转为字符 -> 去除首尾两行，将base64解码以字节流形式写成zip，里面是一张图片，时间隐写

2050502050502050205020202050202020205050205020502050205050505050202050502020205020505050205020206666

20替换0 50替换 1

二进制转字符，然后md5

## UTCTF2020-file-header

题目提示很明显，拿到文件放进010，补上文件头89504e47，得到flag

## 安洵杯-2019-easy-misc

加密的压缩包注释有

```
FLAG IN ((√2524921X85÷5+2)÷15-1794)+NNULLULL,
```

计算可得 7+NNULLULL

掩码爆破

![image](./img/yanma1.png)

得到密码为2019456NNULLULL, 解压后得到如下：

```
a = dIW
b = sSD
c = adE
d = jVf
e = QW8
f = SA=
g = jBt
h = 5RE
i = tRQ
j = SPA
k = 8DS
l = XiE
m = S8S
n = MkF
o = T9p
p = PS5
q = E/S
r = -sd
s = SQW
t = obW
u = /WS
v = SD9
w = cw=
x = ASD
y = FTa
z = AE7
```

binwalk一下图片，可以发现有两张png图片，foremost即可

两张一模一样的图片可以联想到盲水印，跑出一张图片提示11.txt

```py
# -*- coding:utf-8 -*-
alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()_+- =\\{\\}[]"
strings = open('./flag.txt',encoding='utf-8').read()

result = {}
for i in alphabet:
	counts = strings.count(i) # 计算出现的次数
	i = '{0}'.format(i)
	result[i] = counts

res = sorted(result.items(),key=lambda item:item[1],reverse=True)  # 排序操作 True降序
for data in res:
	print(data)

for i in res:
	flag = str(i[0])
	print(flag[0],end="")
```

etaonrhsidluygw 再结合decode.txt

QW8obWdIWT9pMkFSQWtRQjVfXiE/WSFTajBtcw==

base64解码得到Ao(mgHY?i2ARAkQB5_^!?Y!Sj0ms

## MRCTF2020-Hello_misc

图片binwalk后有加密的压缩包，红色的图片拿去stegsolve lsb隐写提取红色0发现有图片格式，save bin下来有密码，解压后文本可知是ttl隐写

隐写后得到0ac1fe6b77be5dbe

解压后发现是文档的格式，更改后缀，打开后全部加深颜色,notepad base64逐行解码得到二进制，0的形状就是flag


## BSidesSF2019-zippy

追踪tcp流

![image](./img/zip1.png)

可以看见是一个压缩包，密码是supercomplexpassword

binwalk分解下输入密码得到flag

## MRCTF2020-不眠之夜

https://mochu.blog.csdn.net/article/details/109649446?spm=1001.2101.3001.6650.1&utm_medium=distribute.pc_relevant.none-task-blog-2%7Edefault%7ECTRLIST%7Edefault-1.no_search_link&depth_1-utm_source=distribute.pc_relevant.none-task-blog-2%7Edefault%7ECTRLIST%7Edefault-1.no_search_link


montage -tile 10x12 -geometry 200x100+0+0 *jpg flag.jpg
gaps --image=flag.jpg --generations=40 --population=120 --size=100


环境失败的话见misc 图片拼接