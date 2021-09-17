# BUUCTF-MISC

- [BUUCTF-MISC](#BUUCTF-MISC)
    - [二维码扫描](#二维码扫描)
    - [Webshell](#Webshell)
    - [神秘龙卷风](#神秘龙卷风)


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