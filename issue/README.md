# ISSUE

## 关于windows下pip安装包不成功的问题

`ValueError: check_hostname requires server_hostname`

临时代理 windows10

```
set HTTPS_PROXY=http://127.0.0.1:7890
set ALL_PROXY=socks5://127.0.0.1:4781
```

永久代理 windows10
https://www.yixuju.cn/other/talking-about-proxy/

## 关于Windows下安装gmpy2

https://blog.csdn.net/x_yhy/article/details/83903367

https://github.com/aleaxit/gmpy/releases/tag/gmpy2-2.1.0a1

>pip install C:\Users\86166\Downloads\gmpy2-2.1.0a1-cp36-cp36m-win_amd64.whl

## pipreqs

如果经常写 python 脚本,可以使用 pipreqs 生成自己的 requirements.txt 文件,这样方便在更换主机的时候快速部署好运行环境

```py
pip install pipreqs
pipreqs ./ --encoding=utf-8
```


## kali下java版本切换

`update-alternatives  --config  java`

**安装其它版本**

https://blog.csdn.net/JakeLinfly/article/details/106853964

## python3.6更新到3.7

https://dev.to/serhatteker/how-to-upgrade-to-python-3-7-on-ubuntu-18-04-18-10-5hab