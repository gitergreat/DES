#ifndef DES_READFILE_H
#define DES_READFILE_H

#include <iostream>
#include <string>
#include <bitset>
#include <fstream>
#include <sstream>
#include <cstdio>
using namespace std;

void read_file_to_string(const char* filename, string& str);//���ļ��е����ݶ����ַ�����
void read_key(const char* filename, string& key_str);
void read_IV(const char* filename, string& VI_str);
void read_cipher_text(const char* filename, string& cipher_text);
void read_plain_text(const char* filename, string& plain_text);
void write_text(const char* filename, string str);//���ܳ�������д���ļ�,���ܳ�������д���ļ�

void read_file_to_string(const char* filename, string& str) {
	fstream file;
	file.open(filename, ios::in);
	getline(file,str);
	//cout<<"�Ѿ��������ַ���"<<str<<endl;
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


