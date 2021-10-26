# CTF-Misc

- [CTF-Misc](#CTF-Misc)
    - [内存取证](#内存取证)
        - [iso](#iso)
        - [Volatility](#Volatility)
    - [文件取证](#文件取证)
        - [Notepad++](#Notepad++)
        - [010editor](#010editor)
            - [编码](#编码)
            - [修改长宽](#修改长宽)
            - [粘贴复制二进制](#粘贴复制二进制)
        - [grep](#grep)
        - [stegsolve](#stegsolve)
        - [右键查看属性](#右键查看属性)
        - [常见文件头](#常见文件头)
        - [binwalk](#binwalk)
        - [foremost](#foremost)
        - [压缩包分析文件头](#压缩包分析文件头)
            - [RAR](#RAR)
        - [加密的压缩包zip](#加密的压缩包zip)
            - [伪加密](#伪加密)
            - [弱密码](#弱密码)
            - [zip-图片](#zip图片)
            - [CRC32爆破](#CRC32爆破)
            - [明文攻击](#明文攻击)
        - [爆破压缩包](#爆破压缩包)
            - [掩码爆破](#掩码爆破)
        - [7z](#7z)
        - [F5-steganography](#F5-steganography)
        - [outguess](#outguess)
        - [base64隐写](#base64隐写)
        - [ScreenToGif](#ScreenToGif)
        - [exiftool](#exiftool)
        - [pyc反编译](#pyc反编译)
        - [pyc隐写](#pyc隐写)
        - [LSB隐写](#LSB隐写)
        - [TTL隐写](#TTL隐写)
        - [logo语言解释器](#logo语言解释器)
    - [流量取证](#流量取证)
        - [wireshark](#wireshark)
            - [tshark](#tshark)
            - [lsass.dmp](#lsass.dmp)
            - [UsbKeyboardDataHacker](#UsbKeyboardDataHacker)
    - [音频取证](#音频取证)
        - [Audacity](#Audacity)
        - [dtmf2um](dtmf2um)
    - [磁盘取证](#磁盘取证)
        - [Ntfs隐写](#Ntfs隐写)
    - [DOC取证](#DOC取证)

- [文章](#文章)
    - https://ctf-wiki.org/misc/introduction/
## 内存取证

### ISO

用foremost分离

### Volatility

Volatility是一款开源内存取证框架，能够对导出的内存镜像进行分析，通过获取内核数据结构，使用插件获取内存的详细情况以及系统的运行状态。

```bash
git clone https://github.com/volatilityfoundation/volatility.git

# pip install pycrypto

官方Github：https://github.com/volatilityfoundation

支持pyhton2: https://github.com/volatilityfoundation/volatility

支持python3：https://github.com/volatilityfoundation/volatility3
```

用法：
```bash
# 先通过 imageinfo 获取系统信息
python2 vol.py -f Target.vmem imageinfo

# 使用hashdump命令获取用户名
python2 vol.py -f Target.vmem --profile=Win7SP1x64 hashdump

# lsadump命令获取最后登录的用户
python2 vol.py -f Target.vmem --profile=Win7SP1x64 lsadump
```

用mimikatz插件获取
```
python2 -m pip install construct
cp mimikatz.py /volatility/plugins/
python2 vol.py  -f tmp.vmem --profile=Win7SP1x64 mimikatz
```

## 文件取证

### Notepad++

右上角插件可转换 hex->Ascii
### 010Editor

**如何导入十六进制文件**

文件->导入十六进制文件
### 编码

### 修改长宽

一般在第二行 6 7列

6是宽 7是高

### 粘贴复制二进制

编辑->粘贴为

编辑->复制为
## grep

linux之用 grep -r 关键字 快速搜索在目录下面的含有关键字的文件

`grep -r 'CTF' ./output `

## stegsolve

Frame Browser:帧浏览器   主要是对GIF之类的动图进行分解，把动图一帧帧的放，有时候会是二维码
### 右键查看属性

右键查看属性-详情信息-备注
### 常见文件头

https://vxhly.github.io/views/windows/file-header-and-tail.html#%E4%BB%8E-ultraedit-%E6%8F%90%E5%8F%96%E7%9A%84%E6%96%87%E4%BB%B6%E5%A4%B4%E4%BF%A1%E6%81%AF

```
JPEG (jpg)，                        　　文件头：FFD8FF E0　　　　　　　　　　　　　　　　　　　　 文件尾：FF D9　　　　　　　　　　　　　　　
PNG (png)，                       　　 文件头：89504E47　　　　　　　　　　　　　　　　　　　　　　文件尾：AE 42 60 82
GIF89 (gif)，                           　　文件头：4749463839　　　　　　　　　　　　　　　　　　　　　　文件尾：00 3B                                                                 ZIP Archive (zip)，                     文件头：504B0304　　　　　　　　　　　　　　　　　　　　　　文件尾：50 4B

TIFF (tif)，                           　  文件头：49492A00　　　　　　　　　　　　　　　　　　　　　　文件尾：
Windows Bitmap (bmp)，      　  文件头：424D　　　　　　　　　　　　　　　　　　　　　　　　 文件尾：
CAD (dwg)，                        　  文件头：41433130　　　　　　　　　　　　　　　　　　　　　　文件尾：
Adobe Photoshop (psd)，          文件头：38425053　　　　　　　　　　　　　　　　　　　　　　文件尾：
Rich Text Format (rtf)，             文件头：7B5C727466　　　　　　　　　　　　　　　　　　　　  文件尾：
XML (xml)，                              文件头：3C3F786D6C　　　　　　　　　　　　　　　　　　　　 文件尾：
HTML (html)，                           文件头：68746D6C3E
Email [thorough only] (eml)，     文件头：44656C69766572792D646174653A
Outlook Express (dbx)，            文件头：CFAD12FEC5FD746F
Outlook (pst)，                         文件头：2142444E
MS Word/Excel (xls.or.doc)，      文件头：D0CF11E0
MS Access (mdb)，                    文件头：5374616E64617264204A
WordPerfect (wpd)，                  文件头：FF575043
Adobe Acrobat (pdf)，               文件头：255044462D312E
Quicken (qdf)，                         文件头：AC9EBD8F
Windows Password (pwl)，         文件头：E3828596

RAR Archive (rar)，                    文件头：526172211A0700 文件尾：0700
Wave (wav)，                            文件头：57415645
AVI (avi)，                                 文件头：41564920
Real Audio (ram)，                     文件头：2E7261FD
Real Media (rm)，                       文件头：2E524D46
MPEG (mpg)，                           文件头：000001BA
MPEG (mpg)，                           文件头：000001B3
Quicktime (mov)，                     文件头：6D6F6F76
Windows Media (asf)，               文件头：3026B2758E66CF11
MIDI (mid)，                              文件头：4D546864
```
### binwalk

```py
python binwalk.py mianju.jpg

# 从图片中分离 -e
python binwalk.py -e mianju.jpg

```

### foremost

kali下用foremost

### 压缩包分析文件头

https://blog.csdn.net/Claming_D/article/details/105899397


#### RAR

![](./img/rar1.png)

```
D5 56 ：HEAD_CRC，2字节，也就是文件头部分的crc校验值
74 ：HEAD_TYPE，1字节，块类型，74表示块类型是文件头
20 90 ：HEAD_FLAGS，2字节，位标记，这块在资料上没找到对应的数值，不知道20 90代表什么意思。
2D 00 ：HEAD_SIZE，2字节，文件头的全部大小（包含文件名和注释）
10 00 00 00 ：PACK_SIZE，4字节，已压缩文件大小
10 00 00 00 ：UNP_SIZE，4字节，未压缩文件大小
02：HOST_OS，1字节，保存压缩文件使用的操作系统，02代表windows
C7 88 67 36：FILE_CRC，4字节，文件的CRC值
6D BB 4E 4B ：FTIME，4字节，MS DOS 标准格式的日期和时间
1D：UNP_VER，1字节，解压文件所需要的最低RAR版本
30：METHOD，1字节，压缩方式，这里是存储压缩
08 00 ：NAME_SIZE，2字节，表示文件名大小，这里文件名大小是8字节（flag.txt）
20 00 00 00 ：ATTR，4字节，表示文件属性这里是txt文件
66 6C 61 67 2E 74 78 74：FILE_NAME（文件名） ，NAME_SIZE字节大小，这里NAME_SIZE大小为8
再往后是txt文件内容，一直到第六行 65 结束，下面是另一个文件块的开始

这个块中存在两个crc值，一个是文件头块中从块类型到文件名这38个字节的校验，后一个则是压缩包中所包含文件的crc校验，解压时，会计算解压后生成文件的crc值，如果等于这里的crc，则解压完成，如果不同，则报错中断。
```
### 加密的压缩包zip


#### 伪加密

用winhex查看全局加密标志和局部加密标志

工具：ZipCenOp.jar

`java -jar ZipCenOp.jar r 111.zip` 解密

#### 弱密码

题目中会有提示或者给出字典，直接爆破
#### zip—图片

一般是隐写题目，从图片中找出密码
#### CRC32爆破

一般用于压缩包里文件内容较短时

CRC32校验爆破原理说明：

CRC32:CRC本身是“冗余校验码”的意思，CRC32则表示会产生一个32bit（8位十六进制数）的校验值。


在产生CRC32时，源数据块的每一位都参与了运算，因此即使数据块中只有一位发生改变也会得到不同的CRC32值，利用这个原理我们可以直接爆破出加密文件的内容。

#### 明文攻击

题给的压缩包里面有一个flag.txt，和刚解压出的txt大小相同，则可以明文攻击

攻击时要注意txt重新压缩

用archpr2明文攻击 - 破解类型 纯文本/明文攻击

爆破时间较长 点击确定保存为zip文件，解压出现flag

![image](./img/mingwengongji.png)
### 爆破压缩包

archpr2 可爆破rar

#### 掩码爆破

archpr工具可掩码爆破

掩码:知道密码中的一部分,只需按规则构造其余部分

15????????.??

结合时间戳

#### 生日爆破

19700000-20000000


### 7z

linux下7z解压vmdk更完整，windows下7z有问题

```bash
7z x flag.vmdk
```

### F5-steganography

```bash
git clone https://github.com/matthewgao/F5-steganography

java Extract 文件
java Extract 文件 -p 密码 -e 输出文件
```


### outguess

```bash
git clone https://github.com/crorvick/outguess
cd outguess
./configure && make && make install

# 加密
outguess -k "my secret key" -d hidden.txt demo.jpg out.jpg

# 解密
 outguess -k "my secret key" -r out.jpg hidden.txt

```

### base64隐写



### ScreenToGif

gif分帧工具

打开编辑器拖进图片即可

### exiftool

跟右键查看属性类似 一个升级版

用于读写和处理图像

"exiftool(-k).exe" attachment.jpg

kali:

`exiftool * | grep flag`

### pyc反编译

https://tool.lu/pyc/

### pyc隐写
https://github.com/AngelKitty/stegosaurus

https://zhuanlan.zhihu.com/p/51226097

Stegosaurus 是一款隐写工具，它允许我们在 Python 字节码文件( pyc 或 pyo )中嵌入任意 Payload 。由于编码密度较低，因此我们嵌入 Payload 的过程既不会改变源代码的运行行为，也不会改变源文件的文件大小。 Payload 代码会被分散嵌入到字节码之中，所以类似 strings 这样的代码工具无法查找到实际的 Payload 。 Python 的 dis 模块会返回源文件的字节码，然后我们就可以使用 Stegosaurus 来嵌入 Payload 了。


python -m stegosaurus aaa.py -s --payload "test{123}"

python stegosaurus.py -x 123.pyc

### LSB隐写

https://github.com/livz/cloacked-pixel

python2 lsb.py extract 1.png 1.txt 123456

### TTL隐写

https://www.cnblogs.com/yunqian2017/p/14671031.html

TTL隐写中用到四个值：00 111111（63）,01 111111（127）,10 111111（191）,11 111111（255）,解密的时候只取前两位，然后转换成ascii

```
IP报文在路由间穿梭的时候每经过一个路由，TTL就会减1，当TTL为0的时候，该报文就会被丢弃。
    TTL所占的位数是8位，也就是0-255的范围，但是在大多数情况下通常只需要经过很小的跳数就能完成报文的转发，
    远远比上限255小得多，所以我们可以用TTL值的前两位来进行传输隐藏数据。
    如：须传送H字符，只需把H字符换成二进制，每两位为一组，每次填充到TTL字段的开头两位并把剩下的6位设置为1（xx111111），这样发4个IP报文即可传送1个字节。
```

### logo语言解释器

```
cs pu lt 90 fd 500 rt 90 pd fd 100 rt 90 repeat 18[fd 5 rt 10]
```

https://www.calormen.com/jslogo/

## 流量取证

### Wireshark

过滤POST包

http.request.method==POST

去掉404

http.response.code !=404

搜索有没有包含"flag"的包

ip.contains "flag"

#### tshark

```
tshark -r sqltest.pcapng -Y "http.request" -T fields -e http.request.full_uri > data.txt
```

-r 读取文件
-Y 过滤语句
-T pdml|ps|text|fields|psml,设置解码结果输出的格式
-e 输出特定字段

http.request.uri http请求的uri部分

#### lsass.dmp

lsass是windows系统的一个进程，用于本地安全和登陆策略。mimikatz可以从 lsass.exe 里获取windows处于active状态账号明文密码。本题的lsass.dmp就是内存运行的镜像，也可以提取到账户密码

https://github.com/gentilkiwi/mimikatz/releases/

以管理员身份运行
```
privilege::debug
sekurlsa::minidump lsass.dmp
sekurlsa::logonpasswords full

```


### UsbKeyboardDataHacker

usb取证 wireshark里全是USB协议流量数据包可用UsbKeyboardDataHacker工具提取

https://github.com/WangYihang/UsbKeyboardDataHacker

`python UsbKeyboardHacker.py data.pcap`


## 音频取证

### Audacity

关于摩斯电码的一个小技巧

文件->导出为wav（若有两个声道，则先分离立体声到单音道）

![image](./img/audacity1.png)


kali(kali右上角要开启声音)
```bash
morse2ascii good.wav
```

![image](./img/audacity.png)

将`t`替换为`-`，e替换为`.`


### dtmf2num

DTMF拨号音识别

dtmf2num.exe girlfriend.wav

![](./img/dtmf1.png)
## 磁盘取证

### Ntfs隐写

工具：NtfsStreamsEditor

虚拟机 有些需要winrar解压才能提取到

## DOC取证

flag有时候把颜色设置为白色 需要全选换成可见颜色

https://www.cnblogs.com/WhiteHatKevil/articles/10051582.html