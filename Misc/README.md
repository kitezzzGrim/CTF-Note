# CTF-Misc

- [CTF-Misc](#CTF-Misc)
    - [内存取证](#内存取证)
        - [Volatility](#Volatility)
    - [文件取证](文件取证)
        - [binwalk](#binwalk)
        - [爆破压缩包](#爆破压缩包)
        - [7z](#7z)

## 内存取证

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

### binwalk

```py
python binwalk.py mianju.jpg

# 从图片中分离 -e
python binwalk.py -e mianju.jpg

```

### 爆破压缩包

archpr2 可爆破rar

### 7z

linux下7z解压vmdk更完整，windows下7z有问题

```bash
7z x flag.vmdk
```

