# python内置函数
- [进制转换](#进制转换)
- [ASCII码](#ASCII码)
- [文件操作](#文件操作)
- [字符串](#字符串)
- [编码解码](#编码解码)
- [判断语句](#判断语句)
- [列表](#列表)
- [数字](#数字)

# 进制转换
```py
hex(16)     # 10进制转16进制
oct(8)      # 10进制转8进制
bin(8)      # 10进制转2进制

int('10')       # 字符串转换成10进制整数
int('10',16)    # 字符串转换成16进制整数
int('0x10',16)  # 字符串转换成16进制整数
int('10',8)     # 字符串转换成8进制整数
int('010',8)    # 字符串转换成8进制整数
int('10',2)     # 字符串转换成2进制整数
```
## ASCII码

**介绍**
- chr()  十进制->基础字符
- ord()  字符->十进制符
- bin() 十进制->二进制

**语法**
```py
chr(65)  # 输出 : 'A'
ord('A') # 输出 : 65
bin(10)  # 输出 ：0b1010
```

## 文件操作

**写入文件**
with open('1.txt','r'):
    f.write(line)

**逐行读取文件**
with open('1.txt','r'):
    line = f.readline()

readline()
readlines()

**文件模式**
r rb w wb 区别
r：Python 将会按照编码格式进行解析，read() 操作返回的是str
rb：也即 binary mode，read()操作返回的是bytes


## 字符串

**介绍**
zfill()
str.zfill(width)
width -- 指定字符串的长度。原字符串右对齐，前面填充0。

**语法**
```py
#!/usr/bin/python
str = "this is string example....wow!!!";
print str.zfill(40);
print str.zfill(50);

## 输出结果
## 00000000this is string example....wow!!!
## 000000000000000000this is string example....wow!!!
```

## 编码解码

encode(),decode()

str通过encode()方法可以编码为指定的bytes
反过来，如果我们从网络或磁盘上读取了字节流，那么读到的数据就是bytes。要把bytes变为str，就需要用decode()方法：

## 判断语句

python中，针对 if 后接数字而言，数字 0 表示 false，其余数字为真，即表示 true，例如 if 5、if 30、if 700 都相当于 if true。

## 列表

index() 函数用于从列表中找出某个值第一个匹配项的索引位置。

```py
aList = [123, 'xyz', 'runoob', 'abc']

print "xyz 索引位置: ", aList.index( 'xyz' )
print "runoob 索引位置 : ", aList.index( 'runoob', 1, 3 )

# xyz 索引位置:  1
# runoob 索引位置 :  2
```

## 数字

abs() 函数返回数字的绝对值。