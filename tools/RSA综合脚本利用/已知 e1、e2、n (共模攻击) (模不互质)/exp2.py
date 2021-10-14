import gmpy2, libnum

def exgcd(a, b):
    if b==0: return 1, 0
    x, y = exgcd(b, a%b)
    return y, x-a//b*y

n = 6266565720726907265997241358331585417095726146341989755538017122981360742813498401533594757088796536341941659691259323065631249
e1 = 773
c1 = 3453520592723443935451151545245025864232388871721682326408915024349804062041976702364728660682912396903968193981131553111537349
e2 = 839
c2 = 5672818026816293344070119332536629619457163570036305296869053532293105379690793386019065754465292867769521736414170803238309535

a, b = exgcd(e1, e2)
m = gmpy2.powmod(c1, a, n) * gmpy2.powmod(c2, b, n) % n
print(m)
# print(libnum.n2s(m))