#ifndef CONTRACT_H
#define CONTRACT_H

#include "Web3.h"
#include <ESP8266WiFi.h>
#include "Util.h"
#include "Log.h"
#include "Crypto.h"
#include "cJSON/cJSON.h"
#include <vector>

#define SIGNATURE_LENGTH 64
#define MAX_RLP_ENCODED_SIZE 512

using std::string;
using std::vector;

struct Options
{
    char from[43];
    char to[43];
    char gasPrice[20];
    unsigned long gas;
};

class Contract
{
public:
    Contract(Web3 *_web3, const char *address);
    void SetPrivateKey(const char *key);
    string SetupContractData(const char *func, ...);
    string SendTransaction(uint32_t nonceVal, unsigned long long gasPriceVal, uint32_t gasLimitVal,
                           string *toStr, string *valueStr, string *dataStr);

private:
    Web3 *web3;
    const char *contractAddress;
    Options options;
    Crypto *crypto;

    void GenerateSignature(uint8_t *signature, int *recid, uint32_t nonceVal, unsigned long long gasPriceVal, uint32_t gasLimitVal,
                           string *toStr, string *valueStr, string *dataStr);
    string GenerateContractBytes(const char *func);
    string GenerateBytesForUint(const uint32_t value);
    string GenerateBytesForInt(const int32_t value);
    string GenerateBytesForUIntArray(const vector<uint32_t> *v);
    string GenerateBytesForAddress(const string *v);
    string GenerateBytesForString(const string *value);
    string GenerateBytesForBytes(const char *value, const int len);

    vector<uint8_t> RlpEncode(
        uint32_t nonceVal, unsigned long long gasPriceVal, uint32_t gasLimitVal,
        string *toStr, string *valueStr, string *dataStr);
    void Sign(uint8_t *hash, uint8_t *sig, int *recid);

    size_t RlpEncodeForRawTransaction(
        uint32_t nonceVal, unsigned long long gasPriceVal, uint32_t gasLimitVal,
        string *toStr, string *valueStr, string *dataStr, uint8_t *sig, uint8_t recid,
        uint8_t *outputBuffer, size_t bufferSize);
};

#endif
