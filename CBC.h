//
// Created by Chares_Funs on 2019/5/12.
//

#ifndef DES_TRY_CBC_H
#define DES_TRY_CBC_H

#include "encrypt_decrypt.h"
#include "function.h"
#include "read_file.h"



void encrypt_CBC(bitset<64> key, bitset<64> VI, string plain_text);
void decrypt_CBC(bitset<64>key,bitset<64> IV, string cipher_text);
void decrypt_CBC(bitset<64>key,bitset<64> IV, string cipher_text, int falg);


void encrypt_CBC(bitset<64> key, bitset<64> IV, string plain_text) {
    int group = plain_text.length() / 64;
    string cipher_text;
    for (int i = 0; i < group; i++) {
        bitset<64> plain_bit(plain_text, i * 64, 64);//���ַ������з�Ƭ��ʼ��Ϊbitset
        string temp_cipher_str;
        string temp_bin_to_hex_str;
        plain_bit = plain_bit^IV;
        IV = encrypt(plain_bit, key, temp_cipher_str,0);//����һ�ּ��ܹ��������01���д���temp_cipher_strS
        bin_to_hex(temp_cipher_str, temp_bin_to_hex_str);//����01����ת��Ϊ16�����ַ�������temp_hex_to_bin_str
        cipher_text = cipher_text + temp_bin_to_hex_str;//�Ѹ÷�����ܵ�����ƴ�ӵ������ַ���cipher_text��
        temp_bin_to_hex_str.clear();
        temp_cipher_str.clear();
    }
    //������д���ļ�֮����Ҫ��cipher_text���
    write_text(c_location, cipher_text);
    cipher_text.clear();
    return;
}

void decrypt_CBC(bitset<64>key,bitset<64> IV,string cipher_text) {
    string plaint_text;
    int group = cipher_text.length() / 64;
    bitset<64> temp_bitset;//��������bit����������һ�ֽ���
    cout<<"group="<<group<<endl;
    for (int i = 0; i < group; i++) {
        bitset<64> cipher_bit(cipher_text, i * 64, 64);//���ַ������з�Ƭ��ʼ��Ϊbitset
        bitset<64> plain_bit;
        string temp_cipher_str;//������ܳ���01����
        string temp_bin_to_hex_str;//����01����ת��֮���16��������
        plain_bit = decrypt(cipher_bit, key);
        plain_bit = plain_bit^IV;//���ܳ��ķ�����Ҫ��IV���õ�����
        IV = cipher_bit;
        temp_cipher_str = plain_bit.to_string();
        bin_to_hex(temp_cipher_str, temp_bin_to_hex_str);
        plaint_text = plaint_text + temp_bin_to_hex_str;
        temp_bin_to_hex_str.clear();
        temp_cipher_str.clear();
    }
    write_text(p_location, plaint_text);
    plaint_text.clear();

}

void decrypt_CBC(bitset<64>key,bitset<64> IV,string cipher_text, int flag) {
    string plaint_text;
    string ascii;
    int group = cipher_text.length() / 64;
    bitset<64> temp_bitset;//��������bit����������һ�ֽ���
    cout<<"group="<<group<<endl;
    for (int i = 0; i < group; i++) {
        //cout<<i<<endl;
        bitset<64> cipher_bit(cipher_text, i * 64, 64);//���ַ������з�Ƭ��ʼ��Ϊbitset
        bitset<64> plain_bit;
        string temp_cipher_str;//������ܳ���01����
        string temp_bin_to_hex_str;//����01����ת��֮���16��������
        plain_bit = decrypt(cipher_bit, key);
        plain_bit = plain_bit^IV;//���ܳ��ķ�����Ҫ��IV���õ�����
        IV = cipher_bit;
        temp_cipher_str = plain_bit.to_string();
        bin_to_hex(temp_cipher_str, temp_bin_to_hex_str);
        plaint_text = plaint_text + temp_bin_to_hex_str;
        temp_bin_to_hex_str.clear();
        temp_cipher_str.clear();
    }
    hex_to_Ascii(ascii,plaint_text);
    cout<<ascii<<endl;
    write_text(p_location, ascii);
    plaint_text.clear();

}


#endif //DES_TRY_CBC_H
