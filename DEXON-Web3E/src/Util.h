//
// Created by Okada, Takahiro on 2018/02/11.
//

#ifndef WEB3_UTIL_H
#define WEB3_UTIL_H

#include <ESP8266WiFi.h>
#include <stdint.h>
#include <vector>

//using namespace std;

class Util {
public:
    // RLP implementation
    // reference:
    //     https://github.com/ethereum/wiki/wiki/%5BEnglish%5D-RLP
    static uint32_t        RlpEncodeWholeHeader(uint8_t *header_output, uint32_t total_len);
    static std::vector<uint8_t> RlpEncodeWholeHeaderWithVector(uint32_t total_len);
    static uint32_t        RlpEncodeItem(uint8_t* output, const uint8_t* input, uint32_t input_len);
    static std::vector<uint8_t> RlpEncodeItemWithVector(const std::vector<uint8_t> input);

    static uint32_t        ConvertNumberToUintArray(uint8_t *str, uint32_t val);
    static std::vector<uint8_t> ConvertNumberToVector(uint32_t val);
    static std::vector<uint8_t> ConvertNumberToVector(unsigned long long val);
    static uint32_t        ConvertCharStrToUintArray(uint8_t *out, const uint8_t *in);
    static std::vector<uint8_t> ConvertHexToVector(const uint8_t *in);
    static std::vector<uint8_t> ConvertHexToVector(const std::string* str);
    static char *          ConvertToString(const uint8_t *in);

    static uint8_t HexToInt(uint8_t s);
    static void    VectorToCharStr(char* str, const std::vector<uint8_t> buf);
    static std::string  VectorToString(const std::vector<uint8_t> buf);
    static std::string  ConvertBytesToHex(const uint8_t *bytes, int length);
    static void    ConvertHexToBytes(uint8_t *_dst, const char *_src, int length);
    static std::string  ConvertBase(int from, int to, const char *s);
    static std::string  ConvertDecimal(int decimal, std::string *s);
    static std::string  ConvertString(const char* value);
    static std::string  ConvertHexToASCII(const char *result, size_t length);
    static std::string  InterpretStringResult(const char *result);
    static std::vector<std::string>* InterpretVectorResult(std::string *result);
    static void PadForward(std::string *target, int targetSize);

    static std::vector<std::string>* ConvertCharStrToVector32(const char *resultPtr, size_t resultSize, std::vector<std::string> *result);

    static std::string  ConvertEthToWei(double eth);

    static size_t GetNumberSize(unsigned long long number);
    static size_t RlpEncodeItemSize(size_t itemSize);
    static size_t RlpEncodeListHeader(size_t totalSize, uint8_t *buffer, size_t bufferSize);

private:
    static uint8_t ConvertCharToByte(const uint8_t* ptr);

};

#endif //WEB3_UTIL_H
