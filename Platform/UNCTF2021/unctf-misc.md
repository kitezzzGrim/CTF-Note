# Unctf-Misc

## 电信诈骗

CTFer,你好，我是威震天！其实我在芝加哥大战中没死，现在你只需要打2000RMB到我的银行账户，我就可以用这2000RMB发红包骗取人们的信任，然后穿过股市网络找到震荡波在纽约给我找的新身体，然后我就可以复活了。今天如果你帮了我，复活后我可以入侵股市网络把钱全部给你们。等过了周末，我就让红蜘蛛变成飞机去接你，然后我把红蜘蛛杀了，让你当霸天虎副指挥官，然后我们从南极洲呈扩散式发出霸天虎军队，万军齐发，占领地球，怎么样？为了防止这条消息被擎天柱拦截。我将银行卡号进行了加密，希望你能成功解密。我的银行账户是qi]m^roVibdVbXUU`h
flag格式：unctf{}

考点：变异凯撒

```py
c = "qi]m^roVibdVbXUU`h"

for move in range(0,50):
    flag = ""
    for i in c:
        flag += chr(ord(i)- move)
        move = move -1

    print(flag)
```

## 引大流咯，happy

修改宽高即可

## 倒立洗头

```py
s2 = ''
with open("key.txt",'r') as f:
    data = f.read()
    data = data[::-1]
    # print(data)
    for i in range(0,len(data),2):
        s1 = data[i:i+2]
        s2 += s1[::-1]
        # print(s2)
    with open("key1.txt",'w+') as f1:
        f1.write(s2)
```

或者：

`open('flag.jpg','wb').write(open('key.txt','rb').read()[::-1])`

手动添加jpg文件头，里面有base64，解码是与佛论禅，这里得找到对应网站才能解密