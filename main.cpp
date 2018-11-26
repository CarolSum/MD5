#include <iostream>
#include <string>
#include <cstring>
using namespace std;

// F轮生成函数
#define f(x, y, z) (((x) & (y)) | ((~x) & (z)))
// G轮生成函数
#define g(x, y, z) (((x) & (z)) | ((y) & (~z)))
// H轮生成函数
#define h(x, y, z) ((x) ^ (y) ^ (z))
// I轮生成函数
#define i(x, y, z) ((y) ^ ((x) | (~z)))
// 循环左移函数
#define CLS(num, n) (((num) << (n)) | ((num) >> (32-(n))))

typedef unsigned char bit8;     // bit8表示8位数据
typedef unsigned int bit32;     // bit32表示32位数据

// F轮循环
inline void F(bit32 &a, bit32 b, bit32 c, bit32 d, bit32 x, bit32 s, bit32 t) {
    a += f(b,c,d) + x + t;
    a = CLS(a, s);
    a += b;
};
// G轮循环
inline void G(bit32 &a, bit32 b, bit32 c, bit32 d, bit32 x, bit32 s, bit32 t) {
    a += g(b,c,d) + x + t;
    a = CLS(a, s);
    a += b;
};
// H轮循环
inline void H(bit32 &a, bit32 b, bit32 c, bit32 d, bit32 x, bit32 s, bit32 t) {
    a += h(b,c,d) + x + t;
    a = CLS(a, s);
    a += b;
};
// I轮循环
inline void I(bit32 &a, bit32 b, bit32 c, bit32 d, bit32 x, bit32 s, bit32 t) {
    a += i(b,c,d) + x + t;
    a = CLS(a, s);
    a += b;
};

const bit8 PADDING[64] = { 0x80 };
const char HEX[16] = {
  '0', '1', '2', '3','4', '5', '6', '7',
  '8', '9', 'a', 'b','c', 'd', 'e', 'f'
};

class MyMD5 {
private:
    bool completed;
    bit32 A,B,C,D;      //  ABCD为4个32-bit的寄存器
    string message;     // 原始字符串
    bit8 _digest[16];   // 最终128位的消息摘要
    bit32 lo, hi;       // 记录消息长度(bit), 分高低各32位
    bit8 buffer[64];    // 处理分块的缓冲区，大小为512bit
public:
    MyMD5(const string& msg){
        // 初始化寄存器状态
        A = 0x67452301;
        B = 0xefcdab89;
        C = 0x98badcfe;
        D = 0x10325476;
        completed = false;
        message = msg;
        lo = hi = 0;
    }

    // 将生成的摘要转化为string
    string toString() {
        string res;
        // 将每8位数据转化为2位16进制字符
        for(int i = 0; i < 16; i++){
            int temp = _digest[i];
            res.append(1, HEX[temp / 16]);
            res.append(1, HEX[temp % 16]);
        }
        return res;
    }

    // 生成md5摘要
    void digest(){
        // 对原始字符串进行处理
        process((const bit8*)message.c_str(), message.length());

        bit8 lengthK[8];
        // 将消息总位数转为byte数组
        // DWordToByte(count, lengthK, 2);
        countToByte(lo, lengthK, 0);
        countToByte(hi, lengthK, 4);
        // 得到当前输入缓冲区位置
        bit32 pos = (bit32)((lo >> 3) & 0x3f);
        // 填充的byte数量
        bit32 paddingNum = (pos < 56) ? (56 - pos) : (120 - pos);
        // 对填充的消息尾部进行处理
        process(PADDING, paddingNum);
        // 对消息长度进行处理
        process(lengthK, 8);
        // 将处理后的A,B,C,D输出成byte数组
        countToByte(A, _digest, 0);
        countToByte(B, _digest, 4);
        countToByte(C, _digest, 8);
        countToByte(D, _digest, 12);

        completed = true;
    }

private:
    // 对每输入8*64个bit进行循环压缩，并填充输入缓冲区
    void process(const bit8* input, size_t len){
        // 根据当前读取了多少个byte, 判断下一个byte在输入缓冲区中的位置
        bit32 pos = (bit32)((lo >> 3) & 0x3f);
        bit32 tailLen = 64 - pos;     // 每个分块512bits, 即64*8byte,tailLen表示输入缓冲剩余可容纳的byte数
        bit32 index = 0;

        // 如果输入byte数量比缓冲剩余可容纳的byte数大，即表示可以构成一个512bit分块
        if(len >= tailLen){
            memcpy(&buffer[pos], input, tailLen);
            compress(buffer);
            // 如果能继续构成512bit的分块则继续读取
            for (index = tailLen; index + 63 < len; index += 64) {
                compress(&input[index]);
            }
            pos = 0;
        }

        // 将剩下未处理的byte放进输入缓冲, 待后面填充后处理
        memcpy(&buffer[pos], &input[index], len - index);
        // 更新读取的bit数。这里将输入长度len转为bit的位数需乘8
        lo += ((bit32)len << 3);
        if(lo < ((bit32)len << 3)) hi++;
        hi += ((bit32)len >> 29);
    }

    // 循环压缩函数
    void compress(const bit8 block[64]){
        bit32 a = A, b = B, c = C, d = D;
        bit32 X[16];
        byteToDWord(block, X, 64);
        // F轮 16次迭代
        F(a, b, c, d, X[ 0],  7, 0xd76aa478);
        F(d, a, b, c, X[ 1], 12, 0xe8c7b756);
        F(c, d, a, b, X[ 2], 17, 0x242070db);
        F(b, c, d, a, X[ 3], 22, 0xc1bdceee);
        F(a, b, c, d, X[ 4],  7, 0xf57c0faf);
        F(d, a, b, c, X[ 5], 12, 0x4787c62a);
        F(c, d, a, b, X[ 6], 17, 0xa8304613);
        F(b, c, d, a, X[ 7], 22, 0xfd469501);
        F(a, b, c, d, X[ 8],  7, 0x698098d8);
        F(d, a, b, c, X[ 9], 12, 0x8b44f7af);
        F(c, d, a, b, X[10], 17, 0xffff5bb1);
        F(b, c, d, a, X[11], 22, 0x895cd7be);
        F(a, b, c, d, X[12],  7, 0x6b901122);
        F(d, a, b, c, X[13], 12, 0xfd987193);
        F(c, d, a, b, X[14], 17, 0xa679438e);
        F(b, c, d, a, X[15], 22, 0x49b40821);
        // G轮 16次迭代
        G(a, b, c, d, X[ 1],  5, 0xf61e2562);
        G(d, a, b, c, X[ 6],  9, 0xc040b340);
        G(c, d, a, b, X[11], 14, 0x265e5a51);
        G(b, c, d, a, X[ 0], 20, 0xe9b6c7aa);
        G(a, b, c, d, X[ 5],  5, 0xd62f105d);
        G(d, a, b, c, X[10],  9,  0x2441453);
        G(c, d, a, b, X[15], 14, 0xd8a1e681);
        G(b, c, d, a, X[ 4], 20, 0xe7d3fbc8);
        G(a, b, c, d, X[ 9],  5, 0x21e1cde6);
        G(d, a, b, c, X[14],  9, 0xc33707d6);
        G(c, d, a, b, X[ 3], 14, 0xf4d50d87);
        G(b, c, d, a, X[ 8], 20, 0x455a14ed);
        G(a, b, c, d, X[13],  5, 0xa9e3e905);
        G(d, a, b, c, X[ 2],  9, 0xfcefa3f8);
        G(c, d, a, b, X[ 7], 14, 0x676f02d9);
        G(b, c, d, a, X[12], 20, 0x8d2a4c8a);
        // H轮 16次迭代
        H(a, b, c, d, X[ 5],  4, 0xfffa3942);
        H(d, a, b, c, X[ 8], 11, 0x8771f681);
        H(c, d, a, b, X[11], 16, 0x6d9d6122);
        H(b, c, d, a, X[14], 23, 0xfde5380c);
        H(a, b, c, d, X[ 1],  4, 0xa4beea44);
        H(d, a, b, c, X[ 4], 11, 0x4bdecfa9);
        H(c, d, a, b, X[ 7], 16, 0xf6bb4b60);
        H(b, c, d, a, X[10], 23, 0xbebfbc70);
        H(a, b, c, d, X[13],  4, 0x289b7ec6);
        H(d, a, b, c, X[ 0], 11, 0xeaa127fa);
        H(c, d, a, b, X[ 3], 16, 0xd4ef3085);
        H(b, c, d, a, X[ 6], 23,  0x4881d05);
        H(a, b, c, d, X[ 9],  4, 0xd9d4d039);
        H(d, a, b, c, X[12], 11, 0xe6db99e5);
        H(c, d, a, b, X[15], 16, 0x1fa27cf8);
        H(b, c, d, a, X[ 2], 23, 0xc4ac5665);
        // I轮 16次迭代
        I(a, b, c, d, X[ 0],  6, 0xf4292244);
        I(d, a, b, c, X[ 7], 10, 0x432aff97);
        I(c, d, a, b, X[14], 15, 0xab9423a7);
        I(b, c, d, a, X[ 5], 21, 0xfc93a039);
        I(a, b, c, d, X[12],  6, 0x655b59c3);
        I(d, a, b, c, X[ 3], 10, 0x8f0ccc92);
        I(c, d, a, b, X[10], 15, 0xffeff47d);
        I(b, c, d, a, X[ 1], 21, 0x85845dd1);
        I(a, b, c, d, X[ 8],  6, 0x6fa87e4f);
        I(d, a, b, c, X[15], 10, 0xfe2ce6e0);
        I(c, d, a, b, X[ 6], 15, 0xa3014314);
        I(b, c, d, a, X[13], 21, 0x4e0811a1);
        I(a, b, c, d, X[ 4],  6, 0xf7537e82);
        I(d, a, b, c, X[11], 10, 0xbd3af235);
        I(c, d, a, b, X[ 2], 15, 0x2ad7d2bb);
        I(b, c, d, a, X[ 9], 21, 0xeb86d391);
        A = A + a; B = B + b; C = C + c; D = D + d;
    }

    // 将长度为len的byte数组转化为32位数组
    void byteToDWord(const bit8* input, bit32* output, size_t len) {
        int index = 0;
        for(size_t i = 0; i < len; i += 4){
            // 将每四个byte拼接成一个32位数据
            output[index] = ((bit32)input[i]) | (((bit32)input[i+1]) << 8) | (((bit32)input[i+2]) << 16) | (((bit32)input[i + 3]) << 24);
            index += 1;
        }
    }

    // 将长度为len的32位数组转化为8位数组
    void DWordToByte(const bit32* input, bit8* output, size_t len) {
        int j = 0;
        for(size_t i = 0; i < len; i++){
            output[j++] = (bit8)(input[i] & 0xff);
            output[j++] = (bit8)((input[i] >> 8) & 0xff);
            output[j++] = (bit8)((input[i] >> 16) & 0xff);
            output[j++] = (bit8)((input[i] >> 24) & 0xff);
        }
    }

    // 将32位数据填充到8bit数组的begin位置
    void countToByte(const bit32 input, bit8* output, size_t begin){
        output[begin++] = (bit8)(input & 0xff);
        output[begin++] = (bit8)((input >> 8) & 0xff);
        output[begin++] = (bit8)((input >> 16) & 0xff);
        output[begin++] = (bit8)((input >> 24) & 0xff);
    }
};


int main()
{
    string source;
    cout << "Input the text you want to encrypt: \n";
    cin >> source;
    MyMD5 test(source);
    test.digest();
    cout << test.toString() << endl;
    return 0;
}
