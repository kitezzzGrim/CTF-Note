# CTF-Misc

- [CTF-Misc](#CTF-Misc)
    - [内存取证](#内存取证)
        - [iso](#iso)
        - [Volatility](#Volatility)
    - [文件取证](#文件取证)
        - [010editor](#010editor)
            - [编码](#编码)
            - [修改长宽](#修改长宽)
        - [stegsolve](#stegsolve)
        - [右键查看属性](#右键查看属性)
        - [常见文件头](#常见文件头)
        - [binwalk](#binwalk)
        - [foremost](#foremost)
        - [加密的压缩包zip](#加密的压缩包zip)
            - [伪加密](#伪加密)
            - [弱密码](#弱密码)
            - [zip-图片](#zip图片)
            - [CRC32爆破](#CRC32爆破)
        - [爆破压缩包](#爆破压缩包)
            - [掩码爆破](#掩码爆破)
        - [7z](#7z)
        - [F5-steganography](#F5-steganography)
        - [outguess](#outguess)
        - [base64隐写](#base64隐写)
        - [ScreenToGif](#ScreenToGif)
        - [exiftool](#exiftool)
        - [pyc反编译](#pyc反编译)
        - [LSB隐写](#LSB隐写)
    - [流量取证](#流量取证)
        - [wireshark](#wireshark)
            - [tshark](#tshark)
            - [lsass.dmp](#lsass.dmp)
    - [音频取证](#音频取证)
        - [Audacity](#Audacity)
    - [磁盘取证](#磁盘取证)
        - [Ntfs隐写](#Ntfs隐写)
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

### 010Editor

**如何导入十六进制文件**

文件->导入十六进制文件
### 编码

### 修改长宽

一般在第二行 6 7列

6是宽 7是高
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


### 爆破压缩包

archpr2 可爆破rar

#### 掩码爆破

archpr工具可掩码爆破

掩码:知道密码中的一部分,只需按规则构造其余部分

15????????.??

结合时间戳


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

### LSB隐写

https://github.com/livz/cloacked-pixel

python2 lsb.py extract 1.png 1.txt 123456

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

## 磁盘取证

### Ntfs隐写

工具：NtfsStreamsEditor

虚拟机 有些需要winrar解压才能提取到