#ifndef DES_ENCRYPT_DECRYPT_H
#define	DES_ENCRYPT_DECRYPT_H

#include <iostream>
#include <fstream>
#include <bitset>
#include "function.h"
#include "table.h"
using namespace std;


void complete(string& str);//如果一个分组不足64位，则低位补0
void encrypt(bitset<64> plain, bitset<64> key, string &cipher_text);
void decrypt(bitset<64> cipher, bitset<64>key, string& plain_text);
void generateKeys(bitset<64> key, bitset<48> subKey[16]);
bitset<28> leftShift(bitset<28> k, int shift);
//f函数，输入是一个32位的bitset对象（R）和一个48位的bitset对象（子密钥），返回值是一个32位bitset对象
bitset<32> f_function(bitset<32> r_32, bitset<48> subkey_48);
bitset<64> encrypt(bitset<64> plain, bitset<64>key, string& cipher_text, int falg);
bitset<64> decrypt(bitset<64> cipher, bitset<64>key);

void complete(string& str) {
	int group = 0;
	if (str.length() % 64) {
		group = str.length() / 64 + 1;
		int count = group * 64 - str.length();
		for (unsigned int i = 0; i < count; i++) {
			str = str + "0";
		}
	}
	return;
}

bitset<32> f_function(bitset<32> r_32, bitset<48> subkey_48) {
	//1.先对32位r_32进行E置换
	bitset<48> expand_r;
	for (int i = 0; i < 48; ++i) {
		expand_r[47 - i] = r_32[32 - E[i]];
	}
	//2.然后进行异或
	expand_r = expand_r ^subkey_48;
	//3.输入S盒
	bitset<32> targetR;
    int x = 0;
    for(int i=0; i<48; i=i+6)
    {
        int row = expand_r[47-i]*2 + expand_r[47-i-5];
        int col = expand_r[47-i-1]*8 + expand_r[47-i-2]*4 + expand_r[47-i-3]*2 + expand_r[47-i-4];
        int num = S_BOX[i/6][row][col];
        bitset<4> binary(num);
        targetR[31-x] = binary[3];
        targetR[31-x-1] = binary[2];
        targetR[31-x-2] = binary[1];
        targetR[31-x-3] = binary[0];
        x += 4;
    }
	//4.最后一步进行p置换
	bitset<32> temp = targetR;
	for (int i = 0; i < 32; ++i) {
		targetR[31-i] = temp[32-P[i]];
	}
	return targetR;
}

bitset<28> leftShift(bitset<28> k, int shift)
{
	bitset<28> temp = k;
	for (int i = 27; i >= 0; --i)
	{
		if (i - shift < 0) {
			k[i] = temp[i - shift + 28];
		}
		else {
			k[i] = temp[i - shift];
		}
	}
    return k;
}

void generateKeys(bitset<64> key, bitset<48> subKey[16])
{
	bitset<56> realKey;
	bitset<28> leftKey;
	bitset<28> rightKey;
	bitset<48> compressKey;

	for (int i = 0; i < 56; ++i) {
		realKey[55 - i] = key[64 - PC_1[i]];
	}
	for (int round = 0; round < 16; ++round)
	{
		for (int i = 28; i < 56; ++i) {
			leftKey[i - 28] = realKey[i];
		}
		for (int i = 0; i < 28; ++i) {
			rightKey[i] = realKey[i];
		}
		leftKey = leftShift(leftKey, shiftBits[round]);
		rightKey = leftShift(rightKey, shiftBits[round]);

		for (int i = 28; i<56; ++i) {
			realKey[i] = leftKey[i - 28];
		}
		for (int i = 0; i < 28; ++i) {
			realKey[i] = rightKey[i];
		}
		for (int i = 0; i < 48; ++i) {
			compressKey[47 - i] = realKey[56 - PC_2[i]];
		}
		subKey[round] = compressKey;
	}
}


/**
 *  生成16个48位的子密钥
 */
void generateKeys(bitset<64> key)
{
    bitset<56> realKey;
    bitset<28> left;
    bitset<28> right;
    bitset<48> compressKey;
    // 去掉奇偶标记位，将64位密钥变成56位
    for (int i=0; i<56; ++i)
        realKey[55-i] = key[64 - PC_1[i]];
    // 生成子密钥，保存在 subKeys[16] 中
    for(int round=0; round<16; ++round)
    {
        // 前28位与后28位
        for(int i=28; i<56; ++i)
            left[i-28] = realKey[i];
        for(int i=0; i<28; ++i)
            right[i] = realKey[i];
        // 左移
        left = leftShift(left, shiftBits[round]);
        right = leftShift(right, shiftBits[round]);
        // 压缩置换，由56位得到48位子密钥
        for(int i=28; i<56; ++i)
            realKey[i] = left[i-28];
        for(int i=0; i<28; ++i)
            realKey[i] = right[i];
        for(int i=0; i<48; ++i)
            compressKey[47-i] = realKey[56 - PC_2[i]];
        subKey[round] = compressKey;
    }
}


void encrypt(bitset<64> plain, bitset<64> key, string &cipher_text) {
	bitset<32> right;
	bitset<32> left;
	bitset<32> new_left;
	bitset<48> sub_key[16];//存放16轮子密钥
	bitset<64> cipher;
	bitset<64> current_bits;//处理后的64位明文序列

	//生成16轮子密钥
	generateKeys(key, sub_key);

	//第一步，IP置换
	for (int i = 0; i < 64; i++) {
		current_bits[63 - i] = plain[64 - IP[i]];
	}
	//第二步，获取R0与L0
    for (int i = 32; i < 64; i++) {
        left[i - 32] = current_bits[i];
    }
	for (int i = 0; i < 32; i++) {
		right[i] = current_bits[i];
	}

	//第三步，进行16轮迭代
	for (int round = 0; round < 16; round++) {
		new_left = right;
		right = left ^ f_function(right,sub_key[round]);
		left = new_left;
	}
	//第四步，将经过16轮迭代运算的R16与L16重新合并为64位的密文（R16L16)
	for (int i = 0; i < 32; i++) {
		cipher[i] = left[i];
	}
	for (int i = 32; i < 64; i++) {
		cipher[i] = right[i - 32];
	}
	//第五步，结尾逆置换
	current_bits = cipher;
	for (int i = 0; i < 64; i++) {
		cipher[63 - i] = current_bits[64 - IP_inverse[i]];
	}
	cipher_text = cipher.to_string();
	return;
}

bitset<64> encrypt(bitset<64> plain, bitset<64>key, string& cipher_text, int falg) {
    bitset<32> right;
    bitset<32> left;
    bitset<32> new_left;
    bitset<48> sub_key[16];//存放16轮子密钥
    bitset<64> cipher;
    bitset<64> current_bits;//处理后的64位明文序列

    //生成16轮子密钥
    generateKeys(key, sub_key);

    //第一步，IP置换
    for (int i = 0; i < 64; i++) {
        current_bits[63 - i] = plain[64 - IP[i]];
    }
    //第二步，获取R0与L0
    for (int i = 32; i < 64; i++) {
        left[i - 32] = current_bits[i];
    }
    for (int i = 0; i < 32; i++) {
        right[i] = current_bits[i];
    }

    //第三步，进行16轮迭代
    for (int round = 0; round < 16; round++) {
        new_left = right;
        right = left ^ f_function(right,sub_key[round]);
        left = new_left;
    }
    //第四步，将经过16轮迭代运算的R16与L16重新合并为64位的密文（R16L16)
    for (int i = 0; i < 32; i++) {
        cipher[i] = left[i];
    }
    for (int i = 32; i < 64; i++) {
        cipher[i] = right[i - 32];
    }
    //第五步，结尾逆置换
    current_bits = cipher;
    for (int i = 0; i < 64; i++) {
        cipher[63 - i] = current_bits[64 - IP_inverse[i]];
    }
    cipher_text = cipher.to_string();
    return cipher;
}

void decrypt(bitset<64> cipher, bitset<64>key, string& plain_text) {
	bitset<32> right;
	bitset<32> left;
	bitset<32> temp_left;
	bitset<48> sub_key[16];//存放16轮子密钥
	bitset<64> plain;
	bitset<64> current_bits;//处理后的64位明文序列

	//生成16轮子密钥
	generateKeys(key, sub_key);

	//第一步，IP置换
	for (int i = 0; i < 64; i++) {
		current_bits[63 - i] = cipher[64 - IP[i]];//这里有问题
	}
	//第二步，获取R0与L0
    for (int i = 32; i < 64; i++) {
        left[i - 32] = current_bits[i];
    }
	for (int i = 0; i < 32; i++) {
		right[i] = current_bits[i];
	}

	//第三步，逆序使用16轮子密钥
	for (int round = 0; round < 16; round++) {
		temp_left = right;
		right = left ^ f_function(temp_left,sub_key[15 - round]);
		left = temp_left;
	}

	//第四步，将经过16轮迭代运算的R16与L16重新合并为64位的密文（R16L16)
	for (int i = 0; i < 32; i++) {
		plain[i] = left[i];
	}
	for (int i = 32; i < 64; i++) {
		plain[i] = right[i - 32];
	}
	//第五步，结尾逆置换
	current_bits = plain;
	for (int i = 0; i < 64; i++) {
		plain[63 - i] = current_bits[64 - IP_inverse[i]];
	}
	plain_text = plain.to_string();
	return;
}

bitset<64> decrypt(bitset<64> cipher, bitset<64>key){
    bitset<32> right;
    bitset<32> left;
    bitset<32> temp_left;
    bitset<48> sub_key[16];//存放16轮子密钥
    bitset<64> plain;
    bitset<64> current_bits;//处理后的64位明文序列

    //生成16轮子密钥
    generateKeys(key, sub_key);

    //第一步，IP置换
    for (int i = 0; i < 64; i++) {
        current_bits[63 - i] = cipher[64 - IP[i]];//这里有问题
    }
    //第二步，获取R0与L0
    for (int i = 32; i < 64; i++) {
        left[i - 32] = current_bits[i];
    }
    for (int i = 0; i < 32; i++) {
        right[i] = current_bits[i];
    }

    //第三步，逆序使用16轮子密钥
    for (int round = 0; round < 16; round++) {
        temp_left = right;
        right = left ^ f_function(temp_left,sub_key[15 - round]);
        left = temp_left;
    }

    //第四步，将经过16轮迭代运算的R16与L16重新合并为64位的密文（R16L16)
    for (int i = 0; i < 32; i++) {
        plain[i] = left[i];
    }
    for (int i = 32; i < 64; i++) {
        plain[i] = right[i - 32];
    }
    //第五步，结尾逆置换
    current_bits = plain;
    for (int i = 0; i < 64; i++) {
        plain[63 - i] = current_bits[64 - IP_inverse[i]];
    }
    return plain;
}




#endif // !DES_ENCRYPT_DECRYPT_H

