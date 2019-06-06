//
// Created by Chares_Funs on 2019/5/12.
//

#ifndef DES_TRY_ECB_H
#define DES_TRY_ECB_H

#include "encrypt_decrypt.h"
#include "function.h"
#include "read_file.h"

void encrypt_ECB(bitset<64>key, string plain_text);
void decrytpt_ECB(bitset<64>key, string cipher_text);
void decrytpt_ECB(bitset<64>key, string cipher_text ,int flag);

void encrypt_ECB(bitset<64>key, string plain_text) {
    int group = plain_text.length() / 64;
    string cipher_text;
    for (int i = 0; i < group; i++) {
        bitset<64> plain_bit(plain_text, i * 64, 64);//���ַ������з�Ƭ��ʼ��Ϊbitset
        string temp_cipher_str;
        string temp_bin_to_hex_str;
        encrypt(plain_bit, key, temp_cipher_str);//����һ�ּ��ܹ��������01���д���temp_cipher_str
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

void decrytpt_ECB(bitset<64>key, string cipher_text) {
    string plain_text;
    int group = cipher_text.length() / 64;
    for (int i = 0; i < group; i++) {
        bitset<64> cipher_bit(cipher_text, i * 64, 64);
        string temp_plain_str;
        string temp_bin_to_hex;
        decrypt(cipher_bit, key, temp_plain_str);
        bin_to_hex(temp_plain_str, temp_bin_to_hex);
        plain_text = plain_text + temp_bin_to_hex;
        temp_bin_to_hex.clear();
        temp_plain_str.clear();
    }
    write_text(p_location, plain_text);
    plain_text.clear();
    return;
}

void decrytpt_ECB(bitset<64>key, string cipher_text, int flag) {
    string plain_text;
    string ascii;
    int group = cipher_text.length() / 64;
    for (int i = 0; i < group; i++) {
        bitset<64> cipher_bit(cipher_text, i * 64, 64);
        string temp_plain_str;
        string temp_bin_to_hex;
        decrypt(cipher_bit, key, temp_plain_str);
        bin_to_hex(temp_plain_str, temp_bin_to_hex);
        plain_text = plain_text + temp_bin_to_hex;
        temp_bin_to_hex.clear();
        temp_plain_str.clear();
    }
    hex_to_Ascii(ascii,plain_text);
    write_text(p_location, ascii);
    plain_text.clear();
    return;
}



#endif //DES_TRY_ECB_H
