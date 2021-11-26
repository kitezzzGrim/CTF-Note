#_*_ coding:utf-8 _*_
#!/usr/bin/env python
#Filename:des.py

from desstruct import *
import re

__all__=['desencode']
class DES():
	'''des ����'''
	def __init__(self):
		pass
	#����
	def code(self,from_code,key,code_len,key_len):
		output=""
		trun_len=0
		
		#�����ĺ���Կת��Ϊ������
		code_string=self._functionCharToA(from_code,code_len)
		code_key=self._functionCharToA(key,key_len)
		
		#�����Կ���Ȳ���16����������������0�ķ�ʽ��Ϊ16��������
		if code_len%16!=0:
			real_len=(code_len/16)*16+16
		else:
			real_len=code_len
		
		if key_len%16!=0:
			key_len=(key_len/16)*16+16
		key_len*=4

		#ÿ��16����ռ4λ
		trun_len=4*real_len
		#��ÿ64λ����һ�μ���
		for i in range(0,trun_len,64):
			run_code=code_string[i:i+64]
			l=i%key_len
			run_key=code_key[l:l+64]

			#64λ���ġ���Կ��ʼ�û�
			run_code= self._codefirstchange(run_code)
			run_key= self._keyfirstchange(run_key)
			
			#16�ε���
			for j in range(16):
				
				#ȡ����������32λ
				code_r=run_code[32:64]
				code_l=run_code[0:32]
					
				#64���ҽ���
				run_code=code_r
				
				#�ұ�32λ��չ�û�
				code_r= self._functionE(code_r)
				
				#��ȡ��������Կ
				key_l=run_key[0:28]
				key_r=run_key[28:56]
				key_l=key_l[d[j]:28]+key_l[0:d[j]]
				key_r=key_r[d[j]:28]+key_r[0:d[j]]
				run_key=key_l+key_r
				key_y= self._functionKeySecondChange(run_key)

				#���
				code_r= self._codeyihuo(code_r,key_y)
				
				#S�д���/ѡ��
				code_r= self._functionS(code_r)
				
				#Pת��
				code_r= self._functionP(code_r)
				
				#���
				code_r= self._codeyihuo(code_l,code_r)
				run_code+=code_r
			#32����
			code_r=run_code[32:64]
			code_l=run_code[0:32]
			run_code=code_r+code_l
			
			#��������ת��Ϊ16���ơ����ʼ�û�
			output+=self._functionCodeChange(run_code)
		return output

	#���	
	def _codeyihuo(self,code,key):
		code_len=len(key)
		return_list=''
		for i in range(code_len):
			if code[i]==key[i]:
				return_list+='0'
			else:
				return_list+='1'
		return return_list

	#���Ļ����ĳ�ʼ�û�		 		 							
	def _codefirstchange(self,code):
		changed_code=''
		for i in range(64):
			changed_code+=code[ip[i]-1]
		return changed_code

	#��Կ��ʼ�û�
	def _keyfirstchange (self,key):
		changed_key=''
		for i in range(56):
			changed_key+=key[pc1[i]-1]
		return changed_key

	#���ʼ�û�
	def _functionCodeChange(self, code):
		lens=len(code)/4
		return_list=''
		for i in range(lens):
			list=''
			for j in range(4):
				list+=code[ip_1[i*4+j]-1]
			return_list+="%x" %int(list,2)
		return return_list
	
	#��չ�û�	
	def _functionE(self,code):
		return_list=''
		for i in range(48):
			return_list+=code[e[i]-1]
		return return_list		
	
	#�û�P		
	def _functionP(self,code):
		return_list=''
		for i in range(32):
			return_list+=code[p[i]-1]
		return return_list

	#S�д���ѡ���û�
	def _functionS(self, key):
		return_list=''
		for i in range(8):
			row=int( str(key[i*6])+str(key[i*6+5]),2)
			raw=int(str( key[i*6+1])+str(key[i*6+2])+str(key[i*6+3])+str(key[i*6+4]),2)
			return_list+=self._functionTos(s[i][row][raw],4)

		return return_list
		
	#��Կ�û�ѡ��2
	def _functionKeySecondChange(self,key):
		return_list=''
		for i in range(48):
			return_list+=key[pc2[i]-1]
		return return_list
	
	#��ʮ������ת��Ϊ�������ַ���
	def _functionCharToA(self,code,lens):
		return_code=''
		lens=lens%16
		for key in code:
			code_ord=int(key,16)
			return_code+=self._functionTos(code_ord,4)		
		if lens!=0:
			return_code+='0'*(16-lens)*4
		return return_code
	
	#������ת��
	def _functionTos(self,o,lens):
		return_code=''
		for i in range(lens):
			return_code=str(o>>i &1)+return_code
		return return_code

#��unicode�ַ�ת��Ϊ16����
def tohex(string):
	return_string=''
	for i in string:
		return_string+="%02x"%ord(i)
	return return_string
		
def tounicode(string):
	return_string=''
	string_len=len(string)
	for i in range(0,string_len,2):
		return_string+=chr(int(string[i:i+2],16))
	return return_string

#��ں���
def desencode(from_code,key):
	
	#ת��Ϊ16����
	from_code=tohex(from_code)
	key=tohex(key)
	
	des=DES()
	key_len=len(key)
	string_len=len(from_code)		
		
	if string_len<1 or key_len<1:
		print 'error input'
		return False
	key_code= des.code(from_code,key,string_len,key_len)
	return key_code

#����
if __name__  == '__main__':
	print("DES ����\n")
	m=raw_input("���������ģ����Ȳ��ޣ�:")
	k=raw_input("��������Կ�����Ȳ��ޣ�:")
	print desencode(m,k)
	k=raw_input("��ȷ���˳�")
