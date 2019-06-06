#include <iostream>
#include "ECB.h"
#include "CBC.h"
using namespace std;

int main(int argc ,char** argv) {
	string temp_str;
	string str_key;
	string plain_text;
	string cipher_text;
	string IV_str;
	if(get_option(argc,argv) == -1){
		cout<<"Input command error!"<<endl;
		return 0;
	}
	//ECB加密模式
	if (model == 0 && crypt == 1 && flag == 1) {
		//把明文读入字符串
		read_plain_text(p_location, temp_str);
		hex_to_bin(temp_str, plain_text);
		cout<<"plaint text ="<<plain_text<<endl;
		temp_str.clear();
		complete(plain_text);
		//把密钥读入字符串
		read_key(k_location, temp_str);
		hex_to_bin(temp_str, str_key);
		bitset<64> key(str_key);
		cout<<"key = "<<key<<endl;
		temp_str.clear();
		encrypt_ECB(key, plain_text);
	}

	//ECB解密模式
	if (model == 0 && crypt == 0 && flag == 1) {
		read_plain_text(c_location, temp_str);
		hex_to_bin(temp_str, cipher_text);
		//把密钥读入字符串
		read_key(k_location, temp_str);
		hex_to_bin(temp_str, str_key);
		bitset<64> key(str_key);
		temp_str.clear();
		decrytpt_ECB(key, cipher_text);
	}

	//CBC加密模式
	if (model == 1 && crypt == 1 && flag == 1) {
		//把明文读入字符串
		read_plain_text(p_location, temp_str);
		hex_to_bin(temp_str, plain_text);
		temp_str.clear();
		complete(plain_text);
		//把密钥读入字符串
		read_key(k_location, temp_str);
		hex_to_bin(temp_str, str_key);
		bitset<64> key(str_key);
		temp_str.clear();

		read_IV(v_location, temp_str);
		hex_to_bin(temp_str, IV_str);
		bitset<64> IV(IV_str);
		temp_str.clear();
		//CBC模式加密
		encrypt_CBC(key, IV, plain_text);
	}

	//CBC解密模式
	if (model == 1 && crypt == 0 && flag == 1) {
		//把密文读入字符串
		read_cipher_text(c_location, temp_str);
		hex_to_bin(temp_str, cipher_text);
		temp_str.clear();
		//把密钥读入字符串
		read_key(k_location, temp_str);
		hex_to_bin(temp_str, str_key);
		bitset<64> key(str_key);
		temp_str.clear();

		read_IV(v_location, temp_str);
		hex_to_bin(temp_str, IV_str);
		bitset<64> IV(IV_str);
		temp_str.clear();
		//CBC模式解密
		decrypt_CBC(key, IV, cipher_text);
	}

	//读入文本为ASCII码的 ECB 加密
	if (model == 0 && crypt == 1 && flag == 0) {
		//把明文读入字符串
		string hex;
		read_plain_text(p_location, temp_str);
		Ascii_to_hex(temp_str,hex);
		hex_to_bin(hex, plain_text);
		cout<<"plaint text ="<<plain_text<<endl;
		temp_str.clear();
		hex.clear();
		complete(plain_text);
		//把密钥读入字符串
		read_key(k_location, temp_str);
		hex_to_bin(temp_str, str_key);
		bitset<64> key(str_key);
		cout<<"key = "<<key<<endl;
		temp_str.clear();
		encrypt_ECB(key, plain_text);
	}
	//ECB解密模式，输入的文件为ASCII
	if (model == 0 && crypt == 0 && flag == 0) {
		string wirte;
		read_plain_text(c_location, temp_str);
		hex_to_bin(temp_str, cipher_text);
		//把密钥读入字符串
		read_key(k_location, temp_str);
		hex_to_bin(temp_str, str_key);
		bitset<64> key(str_key);
		temp_str.clear();
		decrytpt_ECB(key, cipher_text,0);

	}

	//CBC加密模式 ascii模式
	if (model == 1 && crypt == 1 && flag == 0) {
		//把明文读入字符串
		string hex;
		read_plain_text(p_location, temp_str);
		Ascii_to_hex(temp_str,hex);
		hex_to_bin(hex, plain_text);
		temp_str.clear();
		hex.clear();
		complete(plain_text);
		//把密钥读入字符串
		read_key(k_location, temp_str);
		hex_to_bin(temp_str, str_key);
		bitset<64> key(str_key);
		temp_str.clear();

		read_IV(v_location, temp_str);
		hex_to_bin(temp_str, IV_str);
		bitset<64> IV(IV_str);
		temp_str.clear();
		//CBC模式加密
		encrypt_CBC(key, IV, plain_text);
	}

	//CBC解密模式
	if (model == 1 && crypt == 0 && flag == 0) {
		//把密文读入字符串
		read_cipher_text(c_location, temp_str);
		hex_to_bin(temp_str, cipher_text);
		temp_str.clear();
		//把密钥读入字符串
		read_key(k_location, temp_str);
		hex_to_bin(temp_str, str_key);
		bitset<64> key(str_key);
		temp_str.clear();

		read_IV(v_location, temp_str);
		hex_to_bin(temp_str, IV_str);
		bitset<64> IV(IV_str);
		temp_str.clear();
		//CBC模式解密
		decrypt_CBC(key, IV, cipher_text, 0);
	}






	return 0;
}
