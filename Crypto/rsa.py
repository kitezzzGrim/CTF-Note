# 已知p q e 求 n

# 在一次RSA密钥对生成中，假设p=473398607161，q=4511491，e=17

import gmpy2
p = 473398607161
q = 4511491
e = 17
n = (p-1)*(q-1)
d = gmpy2.invert(e,n)
print(d)
