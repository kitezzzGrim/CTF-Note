> 该项目主要记录CTF中用到的工具

- [Python](#Python)
    - [base64解码输出字节文本](#base64解码输出字节文本)
    - [base64隐写加密与解密](#base64隐写加密与解密)
    - [base64连续解码](#base64连续解码)
    - [CRC32校验爆破](#CRC32校验爆破)
    - [字频统计分析](#字频统计分析)
    - [文件异或](#文件异或)
        - [二进制异或](#二进制异或)
    - [进制转化字符脚本](#进制转化字符脚本)
    - [批量解压压缩包+带密码](#批量解压压缩包+带密码)
    - [批量修改文件名后缀](#批量修改文件名后缀)
    - [变异凯撒](#变异凯撒)
    - [RGB转图片](#RGB转图片)
    - [TTL隐写](#TTL隐写)
    - [md5爆破](#md5爆破)
    - [RSA](RSA)
        - [已知 p、q、dp、dq、c 求明文 m (dp、dq 泄露)](#)
        - [已知 e1、e2、n (共模攻击) (模不互质)](#)
        - [已知 n、e、dp、c，求m (dp 泄露)](#)
        - [已知 public key、密文 c，求明文 m (公钥提取)](#)
        - [已知 n、e、c、p、q 批量求 m (n 分解) (Roll 按行加密)](#)
        - [e=3 (小公钥指数攻击) (小明文攻击) (tereotyped messages攻击)](#)
- [监听工具](#监听工具)
    - [Platypus](#Platypus)



## 常用搜索一句话

find / -name flag*


# Python

# 监听工具

## Platypus

项目地址：https://github.com/WangYihang/Platypus

项目教程：https://platypus-reverse-shell.vercel.app/quick-start/
