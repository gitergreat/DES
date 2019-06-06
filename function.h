#ifndef DES_FUNCTION_H
#define DES_FUNCTION_H
#define LOCSIZE 100


#include <iostream>
#include <algorithm>
#include <string>
#include <bitset>
#include <math.h>
#include <sstream>
#include <unistd.h>
#include <getopt.h>
#include <cstring>

using namespace std;


char p_location[LOCSIZE];//明文路径
char k_location[LOCSIZE];//密钥路径
char c_location[LOCSIZE];//密文路径
char v_location[LOCSIZE];//iv路径
int crypt = -1; //加密1 解密0
int flag = -1; //16进制1 acsii 0
int model = -1; //cbc 1  ebc 0

int get_option(int argc, char **argv);
void hex_to_bin(string raw_str, string& result_str);//把十六进制的字符串转换为二进制的01序列
void bin_to_hex(string raw_str, string& result_str);//二进制的01序列转换为十六进制的字符串
void Ascii_to_hex(string ascii, string &hex);
void hex_to_Ascii(string& ascii,string hex);
char hex2Ascii(const char* s);



void hex_to_bin(string raw_str, string& result_str) {
	int temp_num = 0;
	char temp_ch;
	string temp_str;
	for (unsigned int i = 0; i < raw_str.length(); i++) {
		temp_ch = raw_str[i];
		if (temp_ch >= 'A') {
			temp_ch = temp_ch - 55;
		}//如果读取到'A'及以后的字符，这样转换为数字
		
		if (temp_ch >= '0' && temp_ch < 'A') {
			temp_ch = temp_ch - '0';
		}//如果读取到'0'，这样转换为数字

		temp_num = (int)temp_ch;
		while (temp_num) {
			//把单个十六进制数转换为四位二进制，放入temp_str字符串中暂存结果
			//若结果不足四位，则需要在前补0
			if (temp_num % 2 == 0) {
				temp_str = temp_str + "0";
			}
			if (temp_num % 2 == 1) {
				temp_str = temp_str + "1";
			}
			temp_num = temp_num / 2;
		}
		reverse(temp_str.begin(), temp_str.end());
		if (temp_str.length() != 4) {
			int count = 4 - temp_str.length();
			for (int i = 0; i < count; i++) {
				temp_str = "0" + temp_str;
			}
		}
		result_str = result_str + temp_str;
		temp_str.clear();//清空temp_str字符串
	}

	return;
}//把十六进制的字符串转换为二进制的01序列放入字符串result_str中

void bin_to_hex(string raw_str, string& result_str) {
	if (raw_str.length() % 4 != 0) {
		cout << "can not translate binary into hex, lenght error!" << endl;
		return;
	}

	char* form = "0123456789ABCDEF";
	int byte_num = raw_str.length() / 4;
	int count_num = 0;
	int mul_num = 8;
	char* ch_temp = (char*)raw_str.data();
	for (int i = 0; i < byte_num; i++) {
		for (int j = 0; j < 4; j++) {
			count_num = count_num + ((int)ch_temp[j + 4 * i] - 48) * mul_num;
			mul_num = mul_num / 2;
		}
		result_str = result_str + form[count_num];
		count_num = 0;
		mul_num = 8;
	}
}

int get_option(int argc, char **argv){
	int cbc = -1;
	int opt_count = 0;
	int opt;

	while((opt=getopt(argc,argv,"p:m:k:c:v:edha"))!=-1)
	{
		if (opt=='e'||opt=='d')
		{
			if(crypt==-1){
				if(opt=='e') {crypt = 1;}
				else if(opt=='d') {crypt = 0;}
			}
			else{
				cout<<"\"-e\" and \"-d\" cannot appear together!"<<endl;
				return -1;
			}
		}

		if (opt=='h'||opt=='a')
		{
			if(flag==-1){
				if(opt=='h') {flag = 1;}
				else if(opt=='a') {flag = 0;}
			} else {
				cout<<"\"-h\" and \"-a\" cannot appear together!"<<endl;
				return -1;
			}
		}

		if (opt=='m')
		{
			if(strcmp(optarg, "cbc")==0){
				model = 1;
				cbc = 1;
			}else if(strcmp(optarg, "ecb")==0){
				model = 0;
			} else {
				cout<<"\"-m\" should be \"ecb\" or \"cbc\"!"<<endl;
				return -1;
			}
		}

		switch(opt)
		{
			case 'p':
				strcpy(p_location, optarg);
				break;
			case 'k':
				strcpy(k_location, optarg);
				break;
			case 'c':
				strcpy(c_location, optarg);
				break;
			case 'v':
				strcpy(v_location, optarg);
				break;
		}
		opt_count++;
	}

	if (cbc==-1&&opt_count!=6){
		cout<<"the number of options error/unknown options!"<<endl;
		return -1;
	} else if(cbc==1&&opt_count!=7){
		cout<<"the number of options error/unknown options!"<<endl;
		return -1;
	}
	return 0;
}

void Ascii_to_hex(string ascii, string& hex)
{
	char temp;
	string str;
	for(int i=0;i<ascii.length();i++) {
		char b;
		b = ascii[i] % 16;
		if (b < 10) {
			temp = '0' + b;
			str = str + temp;
		} else {
			temp = 'A' + b - 10;
			str = str +temp;
		}
		ascii[i] = ascii[i] / 16;
		b = ascii[i] % 16;
		if (b < 10) {
			temp = '0' + b;
			str = str + temp;
		} else {
			temp = 'A' + b - 10;
			str = str + temp;
		}
		reverse(str.begin(),str.end());
		hex = hex + str;
		str.clear();
	}
}

void hex_to_Ascii(string& ascii,string hex) {
	char ch;
	string temp_str;
	for (int i = 0; i < hex.length(); i = i + 2) {
		temp_str.assign(hex,i,2);
		const char *temp = temp_str.c_str();
		ch = hex2Ascii(temp);
		ascii = ascii + ch;
		temp_str.clear();
	}
	return;
}


char hex2Ascii(const char* s)
{
	int i = 0;
	char n = 0;

	for (; (s[i]>='0' && s[i]<='9') || (s[i]>='a' && s[i]<='z') || (s[i]>='A' && s[i]<='Z'); ++i)
	{
		if (tolower(s[i])>'9') {
			n = 16*n+(10+tolower(s[i])-'a');
		} else {
			n = 16*n+(tolower(s[i])-'0');
		}
	}
	return n;
}



#endif // DES_FUNCTION_H

