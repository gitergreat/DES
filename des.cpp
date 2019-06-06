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
	//ECB����ģʽ
	if (model == 0 && crypt == 1 && flag == 1) {
		//�����Ķ����ַ���
		read_plain_text(p_location, temp_str);
		hex_to_bin(temp_str, plain_text);
		cout<<"plaint text ="<<plain_text<<endl;
		temp_str.clear();
		complete(plain_text);
		//����Կ�����ַ���
		read_key(k_location, temp_str);
		hex_to_bin(temp_str, str_key);
		bitset<64> key(str_key);
		cout<<"key = "<<key<<endl;
		temp_str.clear();
		encrypt_ECB(key, plain_text);
	}

	//ECB����ģʽ
	if (model == 0 && crypt == 0 && flag == 1) {
		read_plain_text(c_location, temp_str);
		hex_to_bin(temp_str, cipher_text);
		//����Կ�����ַ���
		read_key(k_location, temp_str);
		hex_to_bin(temp_str, str_key);
		bitset<64> key(str_key);
		temp_str.clear();
		decrytpt_ECB(key, cipher_text);
	}

	//CBC����ģʽ
	if (model == 1 && crypt == 1 && flag == 1) {
		//�����Ķ����ַ���
		read_plain_text(p_location, temp_str);
		hex_to_bin(temp_str, plain_text);
		temp_str.clear();
		complete(plain_text);
		//����Կ�����ַ���
		read_key(k_location, temp_str);
		hex_to_bin(temp_str, str_key);
		bitset<64> key(str_key);
		temp_str.clear();

		read_IV(v_location, temp_str);
		hex_to_bin(temp_str, IV_str);
		bitset<64> IV(IV_str);
		temp_str.clear();
		//CBCģʽ����
		encrypt_CBC(key, IV, plain_text);
	}

	//CBC����ģʽ
	if (model == 1 && crypt == 0 && flag == 1) {
		//�����Ķ����ַ���
		read_cipher_text(c_location, temp_str);
		hex_to_bin(temp_str, cipher_text);
		temp_str.clear();
		//����Կ�����ַ���
		read_key(k_location, temp_str);
		hex_to_bin(temp_str, str_key);
		bitset<64> key(str_key);
		temp_str.clear();

		read_IV(v_location, temp_str);
		hex_to_bin(temp_str, IV_str);
		bitset<64> IV(IV_str);
		temp_str.clear();
		//CBCģʽ����
		decrypt_CBC(key, IV, cipher_text);
	}

	//�����ı�ΪASCII��� ECB ����
	if (model == 0 && crypt == 1 && flag == 0) {
		//�����Ķ����ַ���
		string hex;
		read_plain_text(p_location, temp_str);
		Ascii_to_hex(temp_str,hex);
		hex_to_bin(hex, plain_text);
		cout<<"plaint text ="<<plain_text<<endl;
		temp_str.clear();
		hex.clear();
		complete(plain_text);
		//����Կ�����ַ���
		read_key(k_location, temp_str);
		hex_to_bin(temp_str, str_key);
		bitset<64> key(str_key);
		cout<<"key = "<<key<<endl;
		temp_str.clear();
		encrypt_ECB(key, plain_text);
	}
	//ECB����ģʽ��������ļ�ΪASCII
	if (model == 0 && crypt == 0 && flag == 0) {
		string wirte;
		read_plain_text(c_location, temp_str);
		hex_to_bin(temp_str, cipher_text);
		//����Կ�����ַ���
		read_key(k_location, temp_str);
		hex_to_bin(temp_str, str_key);
		bitset<64> key(str_key);
		temp_str.clear();
		decrytpt_ECB(key, cipher_text,0);

	}

	//CBC����ģʽ asciiģʽ
	if (model == 1 && crypt == 1 && flag == 0) {
		//�����Ķ����ַ���
		string hex;
		read_plain_text(p_location, temp_str);
		Ascii_to_hex(temp_str,hex);
		hex_to_bin(hex, plain_text);
		temp_str.clear();
		hex.clear();
		complete(plain_text);
		//����Կ�����ַ���
		read_key(k_location, temp_str);
		hex_to_bin(temp_str, str_key);
		bitset<64> key(str_key);
		temp_str.clear();

		read_IV(v_location, temp_str);
		hex_to_bin(temp_str, IV_str);
		bitset<64> IV(IV_str);
		temp_str.clear();
		//CBCģʽ����
		encrypt_CBC(key, IV, plain_text);
	}

	//CBC����ģʽ
	if (model == 1 && crypt == 0 && flag == 0) {
		//�����Ķ����ַ���
		read_cipher_text(c_location, temp_str);
		hex_to_bin(temp_str, cipher_text);
		temp_str.clear();
		//����Կ�����ַ���
		read_key(k_location, temp_str);
		hex_to_bin(temp_str, str_key);
		bitset<64> key(str_key);
		temp_str.clear();

		read_IV(v_location, temp_str);
		hex_to_bin(temp_str, IV_str);
		bitset<64> IV(IV_str);
		temp_str.clear();
		//CBCģʽ����
		decrypt_CBC(key, IV, cipher_text, 0);
	}






	return 0;
}
