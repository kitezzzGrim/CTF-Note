import base64

def base64decoding(src):
    for i in range(2):
        src = base64.b64decode(src).decode()
    return src

if __name__ == "__main__":
    with open("./flag.txt",'r') as f:
        lines = f.readlines()
        for line in lines:
            # print(line)
            steg_line = line.replace('\n','')
            steg_line = base64decoding(steg_line)
            print(steg_line)
