## vmware安装ubuntu16.04

>文章作者 [0xC4SE](https://github.com/0xC4SE)

首先到镜像站下载ubuntu16.04桌面版的iso镜像文件。

https://mirrors.tuna.tsinghua.edu.cn/ubuntu-releases/16.04.7/

这里我选择到清华镜像站下载`ubuntu-16.04.7-desktop-amd64.iso`镜像文件

![](https://gitee.com/t0rped0/image-bed/raw/master/md/1634280741536.png)

然后打开vmware workstation进行安装

选择文件，新建虚拟机

![](https://gitee.com/t0rped0/image-bed/raw/master/md/1628241554060.png)

选择典型，然后点击下一步

![](https://gitee.com/t0rped0/image-bed/raw/master/md/1628241550633.png)

选择稍后安装操作系统

![](https://gitee.com/t0rped0/image-bed/raw/master/md/1628241547507.png)

选择linux，然后版本选择ubuntu 64位，点击下一步

![](https://gitee.com/t0rped0/image-bed/raw/master/md/1628241544761.png)

为虚拟级命名，选择磁盘空闲大的位置放置接下来的虚拟机文件

![](https://gitee.com/t0rped0/image-bed/raw/master/md/1628241541994.png)



这里最大磁盘大小选择20GB(如果后续一直使用的话，可以选择更大如30GB)，然后点击存储为单个文件，下一步

![](https://gitee.com/t0rped0/image-bed/raw/master/md/1628241539244.png)

创建完成后，会出现如下界面，点击编辑虚拟机设置

![](https://gitee.com/t0rped0/image-bed/raw/master/md/1628241536550.png)

点击CD/DVD，选择我们下载的ubuntu.iso镜像文件

![](https://gitee.com/t0rped0/image-bed/raw/master/md/1628241532863.png)

网络适配器桥接和nat接都可以，我这里选择桥接，点击确定

![](https://gitee.com/t0rped0/image-bed/raw/master/md/1628241529132.png)

完成后点击开启虚拟机，出现如下界面，选择中文简体后安装ubuntu

![](https://gitee.com/t0rped0/image-bed/raw/master/md/1628241525773.png)

继续

![](https://gitee.com/t0rped0/image-bed/raw/master/md/1628241522399.png)

清除整个磁盘，点击现在安装

![](https://gitee.com/t0rped0/image-bed/raw/master/md/1628241519852.png)

继续

![](https://gitee.com/t0rped0/image-bed/raw/master/md/1628241516997.png)

继续

![](https://gitee.com/t0rped0/image-bed/raw/master/md/1628241514231.png)

继续

![](https://gitee.com/t0rped0/image-bed/raw/master/md/1628241508856.png)

输入用户名(我这里是test)，计算机名(随便)，输入设置的密码，继续

![](https://gitee.com/t0rped0/image-bed/raw/master/md/1628241506071.png)

等待安装，出现如下界面然后重启

![](https://gitee.com/t0rped0/image-bed/raw/master/md/1628241502545.png)

此时发现一直黑屏，无法继续

![](https://gitee.com/t0rped0/image-bed/raw/master/md/1628241498616.png)

右击虚拟机，选择电源，关机

![](https://gitee.com/t0rped0/image-bed/raw/master/md/1628241495450.png)

继续打开设置，进入CD/DVD，关闭启动时链接

![](https://gitee.com/t0rped0/image-bed/raw/master/md/1628241492654.png)

开机后，右击虚拟机点击安装vmware-tools

先在桌面新建一个文件夹

![](https://gitee.com/t0rped0/image-bed/raw/master/md/1628241489992.png)

然后双击打开vmware-tools提取到桌面文件夹

![](https://gitee.com/t0rped0/image-bed/raw/master/md/1628241487071.png)

提取成功后，进入vmware-tools文件夹，右击打开终端

![](https://gitee.com/t0rped0/image-bed/raw/master/md/1628241483666.png)

进入终端后，首先进入root用户，然后`./vmware-install.p.`进行安装，输入y，一直回车就行

![](https://gitee.com/t0rped0/image-bed/raw/master/md/1628241479733.png)

此时分辨率变得适配屏幕

![](https://gitee.com/t0rped0/image-bed/raw/master/md/1628241476716.png)

现在首先安装`apt-transport-https`


`sudo apt-get install apt-transport-https`


vim /etc/apt/sources.list

替换清华源
```
deb http://mirrors.tuna.tsinghua.edu.cn/ubuntu/ xenial main restricted
deb http://mirrors.tuna.tsinghua.edu.cn/ubuntu/ xenial-updates main restricted
deb http://mirrors.tuna.tsinghua.edu.cn/ubuntu/ xenial universe
deb http://mirrors.tuna.tsinghua.edu.cn/ubuntu/ xenial-updates universe
deb http://mirrors.tuna.tsinghua.edu.cn/ubuntu/ xenial multiverse
deb http://mirrors.tuna.tsinghua.edu.cn/ubuntu/ xenial-updates multiverse
deb http://mirrors.tuna.tsinghua.edu.cn/ubuntu/ xenial-backports main restricted universe multiverse
deb http://mirrors.tuna.tsinghua.edu.cn/ubuntu/ xenial-security main restricted
deb http://mirrors.tuna.tsinghua.edu.cn/ubuntu/ xenial-security universe
deb http://mirrors.tuna.tsinghua.edu.cn/ubuntu/ xenial-security multiverse
```


![](https://gitee.com/t0rped0/image-bed/raw/master/md/1628241472183.png)

然后，虚拟机打开浏览器，所有ubuntu16.04的清华源

![](https://gitee.com/t0rped0/image-bed/raw/master/md/1628241468720.png)

进入`/etc/apt/`目录

![](https://gitee.com/t0rped0/image-bed/raw/master/md/1628241465523.png)

以root权限打开source.list，把我们的源复制进去，然后把其他的源用#注释掉

![](https://gitee.com/t0rped0/image-bed/raw/master/md/1628241461797.png)

更新源

![](https://gitee.com/t0rped0/image-bed/raw/master/md/1628241455964.png)



## 基础依赖环境

```shell
sudo apt update
sudo apt install python2.7
sudo apt install python3
sudo apt install python-dev
sudo apt install python3-dev
sudo apt install vim
sudo apt install git
sudo apt install gcc
sudo apt install make
sudo apt install gdb
sudo apt install build-essential
sudo apt install g++//前一步已安装
sudo apt install gcc-multilib
sudo apt install python3-pip libssl-dev libffi-dev
sudo apt install tmux//做pwn题不建议用xshell，如果你要用xshell，你需要用到tmux终端窗口管理器
```

**注意：装完基础依赖后，强烈建议拍摄一下快照，防止安装后面的环境出问题后重新安装操作系统**

## pip 的安装

### Ubuntu16.04 python3 的pip的安装

ubuntu 16.04中apt安装的pip版本太低，由于pip --upgrade
```shell
wget https://bootstrap.pypa.io/pip/3.5/get-pip.py
python3 get-pip.py
```

### 在 Ubuntu 16.04上安装 Python2 Pip

在python2中安装pip，由于pip 21.0已经于2021年1月停止对Python 2.7的支持，所以在安装pip 21.0以上版本的时候，会报以下的错误：

```shell
python
Traceback (most recent call last):
  File "get-pip.py", line 24244, in <module>
    main()
  File "get-pip.py", line 199, in main
    bootstrap(tmpdir=tmpdir)
  File "get-pip.py", line 82, in bootstrap
    from pip._internal.cli.main import main as pip_entry_point
  File "/tmp/tmphFBy5C/pip.zip/pip/_internal/cli/main.py", line 60
    sys.stderr.write(f"ERROR: {exc}")
                                   ^
SyntaxError: invalid syntax
```

所以为了避免以上问题的出现，或者解决上述的问题，需要安装21.0以下版本的pip，具体的方案如下：

启用 universe 源仓库：

```shell
sudo add-apt-repository universe
```

更新软件包索引：

```shell
sudo apt update
```

使用wget命令来下载get-pip.py脚本：

```shell
wget https://bootstrap.pypa.io/pip/2.7/get-pip.py
```

使用 python2运行脚本来为 Python 2 安装 pip：

```shell
sudo python2 get-pip.py
```

## pwntools安装

ubuntu16.04安装pwntools3(pwntools2同理)

```shell
pip3 install --ignore-installed psutil --user
pip3 install -U setuptools
pip3 install --upgrade pwntools
```

其他高版本安装pwntools

```shell
sudo pip3 install --ignore-installed psutil --user
sudo pip3 install -U setuptools
sudo pip3 install --upgrade pip
sudo pip3 install --upgrade pwntools
pip3 install --ignore-installed psutil --user
```

如何验证pwntools安装成功
python进入交互，导入pwn库，出现如下字符证明pwntools安装成功

```shell
$ python3
>>> from pwn import *
>>> asm("xor eax,eax")
b'1\xc0'
```

## pwndbg插件安装

```shell
git clone https://github.com/pwndbg/pwndbg.git
echo "source ~/pwndbg/gdbinit.py" >> ~/.gdbinit
```

## one_gadget安装

Ubuntu16.04 需要更新 ruby-2.6！
更新 2.6，方法如下，先添加仓库

```shell
sudo add-apt-repository ppa:brightbox/ruby-ng
sudo apt-get update
```

删除低版本的 ruby

```shell
sudo apt-get purge --auto-remove ruby
```

安装 ruby-2.6 版本

```shell
sudo apt-get install ruby2.6 ruby2.6-dev
```

安装one_gadget

```shell
sudo gem install one_gadget
```

## ropper安装

用 pip 安装 Capstone:

```shell
sudo pip3 install capstone
```

用 pip 安装 filebytes

```shell
sudo pip3 install filebytes
```

安装 Keystone

```shell
sudo pip3 install keystone-engine
```

pip 安装 Ropper

```shell
pip3 install ropper
```

## IDA Pro安装

Windows 安装 IDA
链接：https://pan.baidu.com/s/1MANXQXnBuYN5Hfk_8Dg8Ew 
提取码：iejp 
