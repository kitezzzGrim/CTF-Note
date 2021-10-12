# Python语法
- [正则表达式手册](#正则表达式手册)
- [python-高亮](#python-高亮)
- [ipython3](#ipython3)
- [python-常见函数](#python-常见函数)
- [python-切片](#python-切片)
- [一些蜜汁操作](#一些蜜汁操作)
- [{:02X}](#{:02X})
## 正则表达式手册
https://tool.oschina.net/uploads/apidocs/jquery/regexp.html

## python-高亮

例子
```py
BOLD = '\033[1m'
ENDC = '\033[0m'

def title():
    print(BOLD + '''
    Title: 通达oa版本漏洞测试
    Version: 通达OA 11.3 ~ 11.8
    ''' + ENDC)
```
## ipython3
- 安装ipython
    ```
    kali: sudo apt-get install ipython3
    ipython3
    ```

# python-常见函数
- type() : 输出变量类型

## python-切片
- 切片
    ```
    a=[1,2,3.4,5]
    [-1]    -> [5]
    [:-1]   -> [1,2,3,4]
    [::-1]  -> [5,4,3,2,1]
    [2::-1] -> [3,2,1]
    ```
## 一些蜜汁操作

r告诉python解释器这是原始字符串

## {:02X}

例如print('{:02X}'.format(i))这个输出是将i以16进制输出，当i是15，输出结果是0F；

{:X}16进制标准输出形式

02是2位对齐，左补0形式。