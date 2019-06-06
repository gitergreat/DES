#ifndef DES_READFILE_H
#define DES_READFILE_H

#include <iostream>
#include <string>
#include <bitset>
#include <fstream>
#include <sstream>
#include <cstdio>
using namespace std;

void read_file_to_string(const char* filename, string& str);//把文件中的内容读入字符串中
void read_key(const char* filename, string& key_str);
void read_IV(const char* filename, string& VI_str);
void read_cipher_text(const char* filename, string& cipher_text);
void read_plain_text(const char* filename, string& plain_text);
void write_text(const char* filename, string str);//加密出的密文写入文件,解密出的明文写入文件

void read_file_to_string(const char* filename, string& str) {
	fstream file;
	file.open(filename, ios::in);
	getline(file,str);
	//cout<<"已经读到的字符串"<<str<<endl;
	file.close();
	return;
}

void read_key(const char* filename, string& key_str) {
	read_file_to_string(filename,key_str);
	return;
}

void read_IV(const char* filename, string& VI_str) {
	read_file_to_string(filename, VI_str);
	return;
}

void read_cipher_text(const char* filename, string& cipher_text) {
	read_file_to_string(filename, cipher_text);
	return;
}

void read_plain_text(const char* filename, string& plain_text) {
	read_file_to_string(filename, plain_text);
	return;
}

void write_text(const char* filename, const string cipher_text)
{
	ofstream f(filename, ios::trunc);
	ofstream OsWrite(filename, ofstream::app);
	OsWrite << cipher_text;
	OsWrite.close();
	return;
}

#endif //DES_READFILE_H


