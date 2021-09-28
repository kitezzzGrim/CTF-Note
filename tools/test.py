import binascii

s= 'a' + 'a' + 'a' + 'a'
print(binascii.crc32(1) & 0xffffffff)