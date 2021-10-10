import hashlib
s = "0ipj./)IPJ>?"

zimu = "ipjIPJ"
qita = "./>?0)"


for i in zimu:
    for j in zimu:
        for k in zimu:
            for l in qita:
                for a in qita:
                    for d in qita:
                        str11 = i + j + k + l + a + d
                        str11 = str11.encode("utf-8")
                        with open ("1.txt","a+") as f:
                            hash_get = hashlib.sha1(str11).hexdigest()
                            f.write(hash_get)
                            if str11=="4ce4290a0e47297a34402af8b6d33a3d283125c3":
                                print(str11)
