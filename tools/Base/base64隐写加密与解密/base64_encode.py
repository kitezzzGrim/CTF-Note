# -*- coding: cp936 -*-
import base64

flag = 'Tr0y{Base64isF4n}' #flag
bin_str = ''.join([bin(ord(c)).replace('0b', '').zfill(8) for c in flag]) # תΪ�����Ʋ���0bȥ�� ǰ�����0����8λ
# print(bin_str)
base64chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

with open('0.txt', 'rb') as f0, open('1.txt', 'wb') as f1: #'0.txt'������, '1.txt'���ڴ����д��� base64
    for line in f0.readlines():
        rowstr = base64.b64encode(line.replace('\n', '')) #�������ַ���
        # print(rowstr)
        equalnum = rowstr.count('=') # ����ÿ���ж��ٸ��Ⱥ�
        # print(equalnum)

        if equalnum and len(bin_str):
            offset = int('0b'+bin_str[:equalnum * 2], 2) # ��bin_str��ͷequalnum*2 ��������ת��Ϊʮ��������  0b0101 => 5
            char = rowstr[len(rowstr) - equalnum - 1] # ����Ⱥ�ǰ���ַ�
            # print(char)
            rowstr = rowstr.replace(char, base64chars[base64chars.index(char) + offset])
            print(base64chars[base64chars.index(char) + offset])
            bin_str = bin_str[equalnum*2:]

        f1.write(rowstr + '\n')