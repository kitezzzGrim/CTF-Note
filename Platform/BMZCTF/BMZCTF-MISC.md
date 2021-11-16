# BMZCTF-MISC

- [BMZCTF-MISC](#BMZCTF-MISC)
    - [真正的CTFer](#真正的CTFer)
    - [解不开的秘密](#解不开的秘密)
    - [技协杯-签到](#技协杯-签到)
    - [SDNISC2020_简单数据包](#SDNISC2020_简单数据包)
    - [2018-HEBTUCTF-签到题](#2018-HEBTUCTF-签到题)
    - [2018-HEBTUCTF-你可能需要一个wireshark](#2018-HEBTUCTF-你可能需要一个wireshark)
    - [MISC_你猜猜flag](#MISC_你猜猜flag)
    - [2018-护网杯-迟来的签到题](#2018-护网杯-迟来的签到题)
    - [签到题](#签到题)
    - [日志审计](#日志审计)
    - [哆啦A梦](#哆啦A梦)
    - [flag就在这](#flag就在这)
    - [Fix-it](#Fix-it)
    - [flag](#flag)
    - [宝宝](#宝宝)
    - [赢战2019](#赢战2019)
    - [海量的txt文件](#海量的txt文件)
    - [2018-hackergame-Word-文档](#2018-hackergame-Word-文档)
    - [神秘压缩包](#神秘压缩包)
    - [2020首届祥云杯-到点了](#2020首届祥云杯-到点了)
    - [小明的演讲](#小明的演讲)
    - [Traffic_Light](#Traffic_Light)
    - [SDNISC2020_过去和现在](#SDNISC2020_过去和现在)
    - [2018-QCTF-X-man-A-face](#2018-QCTF-X-man-A-face)
    - [内存取证三项](#内存取证三项)
    - [pcap_analysis](#pcap_analysis)
    - [2018-HEBTUCTF-句末大佬的lsb](#2018-HEBTUCTF-句末大佬的lsb)
    - [533](#533)
    - [memory](#memory)
    - [山东省大学生网络技术大赛-pic](#山东省大学生网络技术大赛-pic)
    - [2020首届祥云杯-进制反转](#2020首届祥云杯-进制反转)
    - [泰湖杯-MISC](#泰湖杯-MISC)


## 真正的CTFer

文件取证->图片分析->修改宽高

![image](./img/ctfer1.png)

flag{d2b5543c2f8aa8229057872dd85ce5a9}


## 解不开的秘密

密码取证->VNC

base16->base64得到

```
Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\Software\RealVNC]

[HKEY_CURRENT_USER\Software\RealVNC\vnclicensewiz]
"_AnlClientId"="8f5cc378-2e1d-4670-80e0-d2d81d882561"
"_AnlSelected"="0"
"_AnlInclRate"="0.0025"

[HKEY_CURRENT_USER\Software\RealVNC\vncserver]

[HKEY_CURRENT_USER\Software\RealVNC\VNCViewer4]
"dummy"=""

[HKEY_CURRENT_USER\Software\RealVNC\VNCViewer4\MRU]
"00"="127.0.0.1"
"Order"=hex:00,01
"01"="127.0.0.1:5900"

[HKEY_CURRENT_USER\Software\RealVNC\WinVNC4]
"Password"=hex:37,5e,be,86,70,b3,c6,f3
"SecurityTypes"="VncAuth"
"ReverseSecurityTypes"="None"
"QueryConnect"=dword:00000000
"PortNumber"=dword:0000170c
"LocalHost"=dword:00000000
"IdleTimeout"=dword:00000e10
"HTTPPortNumber"=dword:000016a8
"Hosts"="+,"
"AcceptKeyEvents"=dword:00000001
"AcceptPointerEvents"=dword:00000001
"AcceptCutText"=dword:00000001
"SendCutText"=dword:00000001
"DisableLocalInputs"=dword:00000000
"DisconnectClients"=dword:00000001
"AlwaysShared"=dword:00000000
"NeverShared"=dword:00000000
"DisconnectAction"="None"
"RemoveWallpaper"=dword:00000000
"RemovePattern"=dword:00000000
"DisableEffects"=dword:00000000
"UseHooks"=dword:00000001
"PollConsoleWindows"=dword:00000001
"CompareFB"=dword:00000001
"Protocol3.3"=dword:00000000
"dummy"=""
```

其中
[HKEY_CURRENT_USER\Software\RealVNC]
"Password"=hex:37,5e,be,86,70,b3,c6,f3

用VNC工具破解https://github.com/x0rz4/vncpwd

`vncpwd.exe 375ebe8670b3c6f3`

![image](./img/vnc1.png)

得到!QAZ2wsx 拿去解压docx

![image](./img/vnc2.png)

flag{aec1294a146b8ece1e3a295e557e198c}

## 技协杯-签到

docx解压

![image](./img/jixiebei1.png)

flag{873f6218-dc48-11ea-a3b9-dca90498a2db}

## SDNISC2020_简单数据包

wireshark打不开，就直接拿去binalk跑，发现有压缩包 直接分离，得到一串字符串，base64解码皆可

flag{sdnisc_net_sQ2X3Q9x}

## 2018-HEBTUCTF-签到题

解压后010在结尾处发现flag

HEBTUCTF{lkfdlfnqwnoidasfmaklmf}

## 2018-HEBTUCTF-你可能需要一个wireshark


追踪POST的第二个HTTP流

![image](./img/wireshark1.png)

SEVCVFVDVEYlN0JmMWFnXzFzX3czbl9kNG8lN0Q=

HEBTUCTF{f1ag_1s_w3n_d4o}

## MISC_你猜猜flag

flag.exe

![image](./img/misc1.png)

输入4 base64解码是 flag好像可以猜出来

将flag.exe拖去binwalk发现压缩包，要密码，ZmxhZ+WlveWDj+WPr+S7peeMnOWHuuadpQ==4

解压后 txt打开mdb搜索flag皆可

## 2018-护网杯-迟来的签到题

提示异或

```py
import base64
import string

flag = ''
a = base64.b64decode('AAoHAR1TIiIkUFUjUFQgVyInVSVQJVFRUSNRX1YgXiJSVyJQVRs=')

for i in string.printable:
    for j in a:
        flag += chr( ord(i) ^ j)
    print(flag + '\n')
```


## 签到题

关注公众号：白帽子社区，回复关键字：BMZCTF 获取flag

BMZCTF{W3lc0me_t0_BMZCTF!}

## 日志审计

```
192.168.0.1 - - [13/Oct/2018:12:38:14  0000] "GET /flag.php?user=hence' AND ORD(MID((SELECT IFNULL(CAST(secret AS CHAR),0x20) FROM haozi.secrets ORDER BY secret LIMIT 0,1),1,1))=102-- pZaF HTTP/1.1" 200 327 "-" "sqlmap/1.2#pip (http://sqlmap.org)"
192.168.0.1 - - [13/Oct/2018:12:38:14  0000] "GET /flag.php?user=hence' AND ORD(MID((SELECT IFNULL(CAST(secret AS CHAR),0x20) FROM haozi.secrets ORDER BY secret LIMIT 0,1),2,1))=108-- pZaF HTTP/1.1" 200 327 "-" "sqlmap/1.2#pip (http://sqlmap.org)"
192.168.0.1 - - [13/Oct/2018:12:38:14  0000] "GET /flag.php?user=hence' AND ORD(MID((SELECT IFNULL(CAST(secret AS CHAR),0x20) FROM haozi.secrets ORDER BY secret LIMIT 0,1),3,1))=97-- pZaF HTTP/1.1" 200 327 "-" "sqlmap/1.2#pip (http://sqlmap.org)"
192.168.0.1 - - [13/Oct/2018:12:38:14  0000] "GET /flag.php?user=hence' AND ORD(MID((SELECT IFNULL(CAST(secret AS CHAR),0x20) FROM haozi.secrets ORDER BY secret LIMIT 0,1),4,1))=103-- pZaF HTTP/1.1" 200 327 "-" "sqlmap/1.2#pip (http://sqlmap.org)"
192.168.0.1 - - [13/Oct/2018:12:38:14  0000] "GET /flag.php?user=hence' AND ORD(MID((SELECT IFNULL(CAST(secret AS CHAR),0x20) FROM haozi.secrets ORDER BY secret LIMIT 0,1),5,1))=123-- pZaF HTTP/1.1" 200 327 "-" "sqlmap/1.2#pip (http://sqlmap.org)"
192.168.0.1 - - [13/Oct/2018:12:38:14  0000] "GET /flag.php?user=hence' AND ORD(MID((SELECT IFNULL(CAST(secret AS CHAR),0x20) FROM haozi.secrets ORDER BY secret LIMIT 0,1),6,1))=109-- pZaF HTTP/1.1" 200 327 "-" "sqlmap/1.2#pip (http://sqlmap.org)"
192.168.0.1 - - [13/Oct/2018:12:38:14  0000] "GET /flag.php?user=hence' AND ORD(MID((SELECT IFNULL(CAST(secret AS CHAR),0x20) FROM haozi.secrets ORDER BY secret LIMIT 0,1),7,1))=97-- pZaF HTTP/1.1" 200 327 "-" "sqlmap/1.2#pip (http://sqlmap.org)"
192.168.0.1 - - [13/Oct/2018:12:38:14  0000] "GET /flag.php?user=hence' AND ORD(MID((SELECT IFNULL(CAST(secret AS CHAR),0x20) FROM haozi.secrets ORDER BY secret LIMIT 0,1),8,1))=121-- pZaF HTTP/1.1" 200 327 "-" "sqlmap/1.2#pip (http://sqlmap.org)"
192.168.0.1 - - [13/Oct/2018:12:38:14  0000] "GET /flag.php?user=hence' AND ORD(MID((SELECT IFNULL(CAST(secret AS CHAR),0x20) FROM haozi.secrets ORDER BY secret LIMIT 0,1),9,1))=105-- pZaF HTTP/1.1" 200 327 "-" "sqlmap/1.2#pip (http://sqlmap.org)"
192.168.0.1 - - [13/Oct/2018:12:38:14  0000] "GET /flag.php?user=hence' AND ORD(MID((SELECT IFNULL(CAST(secret AS CHAR),0x20) FROM haozi.secrets ORDER BY secret LIMIT 0,1),10,1))=121-- pZaF HTTP/1.1" 200 327 "-" "sqlmap/1.2#pip (http://sqlmap.org)"
192.168.0.1 - - [13/Oct/2018:12:38:14  0000] "GET /flag.php?user=hence' AND ORD(MID((SELECT IFNULL(CAST(secret AS CHAR),0x20) FROM haozi.secrets ORDER BY secret LIMIT 0,1),11,1))=97-- pZaF HTTP/1.1" 200 327 "-" "sqlmap/1.2#pip (http://sqlmap.org)"
192.168.0.1 - - [13/Oct/2018:12:38:14  0000] "GET /flag.php?user=hence' AND ORD(MID((SELECT IFNULL(CAST(secret AS CHAR),0x20) FROM haozi.secrets ORDER BY secret LIMIT 0,1),12,1))=104-- pZaF HTTP/1.1" 200 327 "-" "sqlmap/1.2#pip (http://sqlmap.org)"
192.168.0.1 - - [13/Oct/2018:12:38:14  0000] "GET /flag.php?user=hence' AND ORD(MID((SELECT IFNULL(CAST(secret AS CHAR),0x20) FROM haozi.secrets ORDER BY secret LIMIT 0,1),13,1))=101-- pZaF HTTP/1.1" 200 327 "-" "sqlmap/1.2#pip (http://sqlmap.org)"
192.168.0.1 - - [13/Oct/2018:12:38:14  0000] "GET /flag.php?user=hence' AND ORD(MID((SELECT IFNULL(CAST(secret AS CHAR),0x20) FROM haozi.secrets ORDER BY secret LIMIT 0,1),14,1))=105-- pZaF HTTP/1.1" 200 327 "-" "sqlmap/1.2#pip (http://sqlmap.org)"
192.168.0.1 - - [13/Oct/2018:12:38:14  0000] "GET /flag.php?user=hence' AND ORD(MID((SELECT IFNULL(CAST(secret AS CHAR),0x20) FROM haozi.secrets ORDER BY secret LIMIT 0,1),15,1))=49-- pZaF HTTP/1.1" 200 327 "-" "sqlmap/1.2#pip (http://sqlmap.org)"
192.168.0.1 - - [13/Oct/2018:12:38:14  0000] "GET /flag.php?user=hence' AND ORD(MID((SELECT IFNULL(CAST(secret AS CHAR),0x20) FROM haozi.secrets ORDER BY secret LIMIT 0,1),16,1))=57-- pZaF HTTP/1.1" 200 327 "-" "sqlmap/1.2#pip (http://sqlmap.org)"
192.168.0.1 - - [13/Oct/2018:12:38:14  0000] "GET /flag.php?user=hence' AND ORD(MID((SELECT IFNULL(CAST(secret AS CHAR),0x20) FROM haozi.secrets ORDER BY secret LIMIT 0,1),17,1))=54-- pZaF HTTP/1.1" 200 327 "-" "sqlmap/1.2#pip (http://sqlmap.org)"
192.168.0.1 - - [13/Oct/2018:12:38:14  0000] "GET /flag.php?user=hence' AND ORD(MID((SELECT IFNULL(CAST(secret AS CHAR),0x20) FROM haozi.secrets ORDER BY secret LIMIT 0,1),18,1))=53-- pZaF HTTP/1.1" 200 327 "-" "sqlmap/1.2#pip (http://sqlmap.org)"
192.168.0.1 - - [13/Oct/2018:12:38:14  0000] "GET /flag.php?user=hence' AND ORD(MID((SELECT IFNULL(CAST(secret AS CHAR),0x20) FROM haozi.secrets ORDER BY secret LIMIT 0,1),19,1))=97-- pZaF HTTP/1.1" 200 327 "-" "sqlmap/1.2#pip (http://sqlmap.org)"
192.168.0.1 - - [13/Oct/2018:12:38:14  0000] "GET /flag.php?user=hence' AND ORD(MID((SELECT IFNULL(CAST(secret AS CHAR),0x20) FROM haozi.secrets ORDER BY secret LIMIT 0,1),20,1))=101-- pZaF HTTP/1.1" 200 327 "-" "sqlmap/1.2#pip (http://sqlmap.org)"
192.168.0.1 - - [13/Oct/2018:12:38:14  0000] "GET /flag.php?user=hence' AND ORD(MID((SELECT IFNULL(CAST(secret AS CHAR),0x20) FROM haozi.secrets ORDER BY secret LIMIT 0,1),21,1))=55-- pZaF HTTP/1.1" 200 327 "-" "sqlmap/1.2#pip (http://sqlmap.org)"
192.168.0.1 - - [13/Oct/2018:12:38:14  0000] "GET /flag.php?user=hence' AND ORD(MID((SELECT IFNULL(CAST(secret AS CHAR),0x20) FROM haozi.secrets ORDER BY secret LIMIT 0,1),22,1))=53-- pZaF HTTP/1.1" 200 327 "-" "sqlmap/1.2#pip (http://sqlmap.org)"
192.168.0.1 - - [13/Oct/2018:12:38:14  0000] "GET /flag.php?user=hence' AND ORD(MID((SELECT IFNULL(CAST(secret AS CHAR),0x20) FROM haozi.secrets ORDER BY secret LIMIT 0,1),23,1))=54-- pZaF HTTP/1.1" 200 327 "-" "sqlmap/1.2#pip (http://sqlmap.org)"
192.168.0.1 - - [13/Oct/2018:12:38:14  0000] "GET /flag.php?user=hence' AND ORD(MID((SELECT IFNULL(CAST(secret AS CHAR),0x20) FROM haozi.secrets ORDER BY secret LIMIT 0,1),24,1))=57-- pZaF HTTP/1.1" 200 327 "-" "sqlmap/1.2#pip (http://sqlmap.org)"
192.168.0.1 - - [13/Oct/2018:12:38:14  0000] "GET /flag.php?user=hence' AND ORD(MID((SELECT IFNULL(CAST(secret AS CHAR),0x20) FROM haozi.secrets ORDER BY secret LIMIT 0,1),38,1))=125-- pZaF HTTP/1.1" 200 327 "-" "sqlmap/1.2#pip (http://sqlmap.org)"
```

102 108 97 103 123 109 97 121 105 121 97 104 101 105 49 57 54 53 97 101 55 53 54 57 125

flag{mayiyahei1965ae7569}

## 哆啦A梦

binwalk分离出png图片，修改高宽后是二维码，qr扫描即可

![image](./img/duola1.png)

ZmxhZ3tDdGZfMjAxOF92ZXJ5X2dvb2R9

flag{Ctf_2018_very_good}

## flag就在这

无法打开压缩包，010查看补全 50 4B压缩包头

打开后需要密码，用ziperello爆破即可

## Fix-it

用PS修复，快速选择左上角方框，复制图层到右上角和左下角

![image](./img/fix-it.png)

flag{easyQRcode}

## flag

010打开，base64解码可以发现是png格式，利用base64解码转图片

https://the-x.cn/base64

在线转换即可

flag{base64_wow}

## 宝宝

扫描后没啥东西，foremost分离出压缩包

猜测密码为babybaby成功解压

将flag后缀改为png扫描后得到flag

flag{ThIs_Is_QR_Code}

## 赢战2019

foremost分离出二维码，扫描后没啥东西，直接上stegsolve隐写，发现左下角有flag

![image](./img/yingzhan1.png)

flag{You_ARE_SOsmart}

## 海量的txt文件

用grep全局搜索，刚开始flag没搜到，尝试用其它关键词如key

`grep -rn 'key' ./*`

![image](./img/txt1.png)

## 2018-hackergame-Word-文档

改为zip格式，发现flag

## 神秘压缩包

压缩包密码用base64转图片即可

解压后是一堆二维码，可用微微二维码工具批量解压

整理后二进制转字符即可

flag{QRcode1sUseful}

## 2020首届祥云杯-到点了

一共三个文档

第一个文档 打开隐藏文字：提示8位字母数字

第二个文档 需要密码，根据上一个提示 可以看到文档日期刚好8位

20201024

移动图片 全选加颜色 放大

AABBAABBBAABBBAAAABBABBABABAAAAABBAAABBBBAABBBAABABABBAAABAAAABAABAABBABAAAAABAA

培根密码，解密得到

GOODNIGHTSWEETIE

第三个文档 改为zip发现有另外一个压缩包，解压后bmp ，接下来思路是bmp解密，用wbstego4.3open 保存为txt得到flag

## 小明的演讲

下载后ppt文件 改为zip解压 发现有flag.zip以及对应密码密文

第一个 中文电码 2053250813784316 转换为 我是密码

第二个 乱码 用010打开开头改为 FE FF即可正常显示 我也是密码

组合起来就是 我是密码我也是密码 解压得到

c3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3NzZmxhZ3twcHR4cG93ZXJwb2ludH0=

flag{pptxpowerpoint}

## Traffic_Light

用screentogif分离图片

1、发现第2的倍数的图片都是没有灯亮的。忽略不计。
2、绿灯和红灯总和为8或8的倍数时，下一张一定是黄色。
由此可以推断为二进制。绿为1，红为0，黄为空格。
写脚本进行编码：

```py
# -*-coding: utf-8 -*-
from PIL import Image

binstr = ""
flag = ""

def decode(s):
    return ''.join([chr(i) for i in [int(b, 2) for b in s.split(' ')]])

for i in range(1168):
    image=Image.open(r'./202011/'+str(i)+'.png')
    # print (image.getpixel((115,55)))#输出颜色值
    # print (image.getpixel((115,145)))
    tmp1 = image.getpixel((115,55))
    tmp2 = image.getpixel((115,150))
    # print (type(tmp1))
    if(tmp1[0] > 250):
        binstr += '1'
    elif(tmp2[1] > 250):
        binstr += '0'
    else:
        binstr += ''
print (binstr)

for i in range(len(binstr)):
    if i%8==0:
        flag +=decode(binstr[i:i+8])
print(flag)
```

flag{Pl34s3_p4y_4tt3nt10n_t0_tr4ff1c_s4f3ty_wh3n_y0u_4r3_0uts1d3}

## SDNISC2020_过去和现在

binwalk -e分离 在21154发现flag

flag{fc25cbb7b85959fe03738241a96bf23d}

## 2018-QCTF-X-man-A-face

ps补全二维码 但qr扫不出来，微信扫可以

KFBVIRT3KBZGK5DUPFPVG2LTORSXEX2XNBXV6QTVPFZV6TLFL5GG6YTTORSXE7I=

base32解码

QCTF{Pretty_Sister_Who_Buys_Me_Lobster}

## 内存取证三项

一天下午小白出去吃饭，临走之前还不忘锁了电脑，这时同寝室的小黑想搞点事情，懂点黑客和社工知识的小黑经过多次尝试获得了密码成功进入电脑，于是便悄悄在电脑上动起手脚了，便在桌面上写着什么，想给小白一个惊喜，同时还传送着小白的机密文件，正巧这时小白刚好回来，两人都吓了一跳，小黑也不管自己在电脑上留下的操作急忙离开电脑，故作淡定的说：“我就是随便看看”。
1.小黑写的啥，据说是flag？
2.那么问题来了，小白的密码是啥？
3.小黑发送的机密文件里面到底是什么

1.根据提示小黑在使用记事本编写文本

可疑进程
```
explorer.exe 1416
notepad.exe 280
cmd.exe 1568
nc.exe 120
DumpIt.exe 392
```

```
python2 vol.py -f L-12A6C33F43D74-20161114-125252.raw imageinfo

python2 vol.py -f L-12A6C33F43D74-20161114-125252.raw --profile=WinXPSP2x86 pslist

python2 vol.py notepad -f L-12A6C33F43D74-20161114-125252.raw --profile=WinXPSP2x86
```

得到hex值，解码为flag{W3lec0me_7o_For3n5ics}

2.第二个提示需要提取密码

这个需要破解ntlm hash 后面再补

3.第三个查看cmd.exe

```
python2 vol.py -f L-12A6C33F43D74-20161114-125252.raw --profile=WinXPSP2x86 cmdscan

python2 vol.py -f L-12A6C33F43D74-20161114-125252.raw --profile=WinXPSP2x86 dumpfiles -Q 0x0000000002c61318 --dump-dir=./
```

得到zip压缩包，ziperello爆破8位纯数字，提示是生日

## pcap_analysis

在工控系统网关截取了一段流量，请分析这段流量并找出其中利用Modbus协议写寄存器的数据。注意，得到的flag请使用BMZCTF{}格式提交

提示modbus协议，过滤流即可，追踪TCP流拼接flag

BMZCTF{323f986d429a689d3b96ad12dc5cbc701db0af55}

## 2018-HEBTUCTF-句末大佬的lsb

lsb隐写，密码是句末的姓 chen

`python2 lsb.py extract jumo.png 1.txt chen `

HEBTUCTF{wuinoknadsflmladflnef}

## 533

爆破压缩包，提示密码范围为000000000-999999999

用ziperello爆破即可 548751269

爆破出533.zip,该压缩文件下有3个加密的文本

![image](./img/533-1.png)

考点：crc32爆破

![image](./img/crc32-1.png)

flag{CRC32}
## memory

分析内存镜像,破解管理员的登录密码,flag为明文密码的MD5值

```py
python2 vol.py -f memory imageinfo
python2 vol.py -f memory --profile=WinXPSP2x86 hashdump
```

把内存中所有用户的hash全部dump出来

```
Administrator:500:0182bd0bd4444bf867cd839bf040d93b:c22b315c040ae6e0efee3518d830362b:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
HelpAssistant:1000:132893a93031a4d2c70b0ba3fd87654a:fe572c566816ef495f84fdca382fd8bb:::
```

另存为hash.txt

```
john --wordlist=/usr/share/john/password.lst --rule --format=NT hash.txt
```

flag{25f9e794323b453885f5181f1b624d0b}

## 山东省大学生网络技术大赛-pic

stegsolve lsb提取数据发现7z

7z里全是3字节的文本，可以crc32爆破

```py
import binascii
import string

def crack_crc():
    print('-------------Start Crack CRC-------------')
    crc_list = [0x40e61be5,0x91c7b4a0,0xf4fd5e1c,0x02658101,0x92d786fd,0x03b3ea6a]
    comment = ''
    chars = string.printable
    for crc_value in crc_list:
        for char1 in chars:
            for char2 in chars:
                for char3 in chars:
                    res_char = char1 + char2 + char3#获取遍历的任意3Byte字符
                    char_crc = binascii.crc32(res_char.encode())#获取遍历字符的CRC32值
                    calc_crc = char_crc & 0xffffffff#将遍历的字符的CRC32值与0xffffffff进行与运算
                    if calc_crc == crc_value:#将获取字符的CRC32值与每个文件的CRC32值进行匹配
                        print('[+] {}: {}'.format(hex(crc_value),res_char))
                        comment += res_char
    print('-----------CRC Crack Completed-----------')
    print('Result: {}'.format(comment))

if __name__ == '__main__':
    crack_crc()
```

flag{CRC32/233333}

## 2020首届祥云杯-进制反转

电脑中到底使用的是什么进制呢？真是麻烦，有时候还是手机好用。结果用BMZCTF{}包住，并且全为大写

![image](./img/010deitor1.png)

在加密标识处 将1改为0

解压得到flag.wav

音频时间反转-听歌识曲

BMZCTF{TOOGOODATGOODBYES}

## 泰湖杯-MISC

伪加密
```java
java -jar ZipCenOp.jar r 715e25aec2a24ac79ab6e74497cafb80.zip
```

doc隐写 隐藏文字 密钥是网址可以猜出是希尔密码

http://www.atoolbox.net/Tool.php?Id=914

得到love and peaceee

rabbit解密

LR2TMNLCGBOHKNDGGVRFY5JWGZTDAXDVMZTDCYK4OU4GCZRYLR2TSNTCHBOHKNJUMM4VY5JVGBSTOXDVHE3DIZC4OU2TIM3ELR2TQYLGHBOHKOJWGQYFY5JWGQ3DSXDVHE3GEOC4OU2TAZJXLR2TOZRTMROHKOBVME4VY5JVGRQTIXDVHAYDEOC4OU4GCZRYLR2TSNTCHBOHKNRRGY3VY5JVHA2WKXDVHAZDOMS4OU2WGMDBLR2TKNDDHFOHKODGMU3FY5JYMFSTMXDVG5QTOYK4OU3DENBQLR2TSNRUMROHKNRSGEYVY5JVMZTDKXDVHE3GEOC4OU3TSNJXLR2TQYLFGZOHKNLGMY2VY5JVGRRTSXDVHE3DIMC4OU2TMYRULR2TKNDDHFOHKNJWMM4VY5JUMZSWKXDVGU4TGN24OU4TMM3GLR2TMY3FGJOHKOBSG4ZFY5JYGM4GCXDVGVRGGMS4OU4GCZJWLR2TKOBVMVOHKNJUHEZFY5JYGM4GCXDVG43TGZK4OU3DEMJRLR2TKNDDHFOHKNRSGQYFY5JUMYYGMXDVHAYDKZK4OU4DKYJZLR2TSNTCHBOHKNRRGBSFY5JZGVRWIXDVGU2DGNS4OU3DENBQLR2TIZTFMVOHKNRWGJTFY5JYGI3TEXDVGY2DMOK4OU4GCMZWLR2TKNTCGROHKNJUMM4VY5JZHA2TQXDVGYYTAZC4OU2TIYZZLR2TKMZXGNOHKNDGMVSVY5JVGRRTSXDVG5QTOYK4OU4DOMLDLR2TSNRUGBOHKNJWMM4VY5JUMYYGMXDVGVTGMNK4OU2TIYZZLR2TMNBWHFOHKNJUMM4VY5JUMVQTMXDVHAZTQYK4OU2TIYZZLR2TONZTMVOHKNJUME2FY5JVHE4DEXDVHE4DKOC4OU2TSOBS

base32解密

\u65b0\u4f5b\u66f0\uff1a\u8af8\u96b8\u54c9\u50e7\u964d\u543d\u8af8\u9640\u6469\u96b8\u50e7\u7f3d\u85a9\u54a4\u8028\u8af8\u96b8\u6167\u585e\u8272\u5c0a\u54c9\u8fe6\u8ae6\u7a7a\u6240\u964d\u6211\u5ff5\u96b8\u7957\u8ae6\u5ff5\u54c9\u9640\u56b4\u54c9\u56c9\u4fee\u5937\u963f\u6ce2\u8272\u838a\u5bc2\u8ae6\u585e\u5492\u838a\u773e\u6211\u54c9\u6240\u4f0f\u805e\u85a9\u96b8\u610d\u95cd\u5436\u6240\u4fee\u662f\u8272\u6469\u8a36\u56b4\u54c9\u9858\u610d\u54c9\u5373\u4fee\u54c9\u7a7a\u871c\u9640\u56c9\u4f0f\u5ff5\u54c9\u6469\u54c9\u4ea6\u838a\u54c9\u773e\u54a4\u5982\u9858\u5982

unicode解密

新佛曰：諸隸哉僧降吽諸陀摩隸僧缽薩咤耨諸隸慧塞色尊哉迦諦空所降我念隸祗諦念哉陀嚴哉囉修夷阿波色莊寂諦塞咒莊眾我哉所伏聞薩隸愍闍吶所修是色摩訶嚴哉願愍哉即修哉空蜜陀囉伏念哉摩哉亦莊哉眾咤如願如

佛解密

Live beautifully, dream passionately, love completely.

拿去解压得到fun.wav 频谱分析

![image](./img/pinpu1.png)

flag{m1sc_1s_funny2333}

## pcap