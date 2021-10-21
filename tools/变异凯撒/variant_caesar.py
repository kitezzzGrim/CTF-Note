c = "kpdi|C`cp]mY`gfZr"
move = 5

flag = ""
for i in c:
    flag += chr(ord(i)- move)
    move = move -1

print(flag)