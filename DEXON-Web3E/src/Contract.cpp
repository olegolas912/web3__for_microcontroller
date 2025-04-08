//
//

#include "Contract.h"
#include "Web3.h"
#include <ESP8266WiFi.h>
#include "Util.h"
#include "Log.h"
#include "cJSON/cJSON.h"
#include <vector>

#define SIGNATURE_LENGTH 64
#define MAX_RLP_ENCODED_SIZE 512 // Adjust this based on your needs

/**
 * Public functions
 * */

 using std::string;
 using std::vector;


Contract::Contract(Web3* _web3, const char* address) {
    web3 = _web3;
    contractAddress = address;
    options.gas=0;
    strcpy(options.from,"");
    strcpy(options.to,"");
    strcpy(options.gasPrice,"0");
    crypto = NULL;
}

void Contract::SetPrivateKey(const char *key) {
    crypto = new Crypto(web3);
    crypto->SetPrivateKey(key);
}

string Contract::SetupContractData(const char* func, ...)
{
    string ret = "";

    string contractBytes = GenerateContractBytes(func);
    ret = contractBytes;

    size_t paramCount = 0;
    vector<string> params;

    // Safer and more efficient string parsing
    const char* start = strchr(func, '(');
    if (start != nullptr) {
        start++; // Move past the '('
        const char* end = strchr(start, ')');
        if (end != nullptr) {
            string paramStr(start, end - start); // Extract parameters string
            size_t pos = 0;
            string token;
            while ((pos = paramStr.find(",")) != string::npos) {
                token = paramStr.substr(0, pos);
                params.push_back(token);
                paramStr.erase(0, pos + 1);
                paramCount++;
            }
            params.push_back(paramStr); // Last parameter
            paramCount++;
        }
    }

    va_list args;
    va_start(args, func); // Changed to func
    for( int i = 0; i < paramCount; ++i ) {
        if (strstr(params[i].c_str(), "uint") != NULL && strstr(params[i].c_str(), "[]") != NULL)
        {
            // value array
            vector<uint32_t> *arg = va_arg(args, vector<uint32_t> *);
            if (arg != nullptr) {
                string output = GenerateBytesForUIntArray(arg);
                ret = ret + output;
            }
        }
        else if (strncmp(params[i].c_str(), "uint", sizeof("uint")) == 0 || strncmp(params[i].c_str(), "uint256", sizeof("uint256")) == 0)
        {
            uint32_t arg = va_arg(args, uint32_t);
            string output = GenerateBytesForUint(arg);
            ret = ret + output;
        }
        else if (strncmp(params[i].c_str(), "int", sizeof("int")) == 0 || strncmp(params[i].c_str(), "bool", sizeof("bool")) == 0)
        {
            int32_t arg = va_arg(args, int32_t);
            string output = GenerateBytesForInt(arg);
            ret = ret + output;
        }
        else if (strncmp(params[i].c_str(), "address", sizeof("address")) == 0)
        {
            string *arg = va_arg(args, string *);
            if (arg != nullptr) {
                string output = GenerateBytesForAddress(arg);
                ret = ret + output;
            }
        }
        else if (strncmp(params[i].c_str(), "string", sizeof("string")) == 0)
        {
            string *arg = va_arg(args, string *);
            if (arg != nullptr) {
                string output = GenerateBytesForString(arg);
                ret = ret + output;
            }
        }
        else if (strncmp(params[i].c_str(), "bytes", sizeof("bytes")) == 0)
        {
            long len = strtol(params[i].c_str() + 5, nullptr, 10);
            char *arg = va_arg(args, char *);
            if (arg != nullptr) {
                string output = GenerateBytesForBytes(arg, len);
                ret = ret + output;
            }
        }
    }
    va_end(args);

    return ret;
}

// string Contract::ViewCall(const string *param)
// {
//     string result = web3->EthViewCall(param, contractAddress);
//     return result;
// }

// string Contract::Call(const string *param)
// {
//     const string from = string(options.from);
//     const long gasPrice = strtol(options.gasPrice, nullptr, 10);
//     const string value = "";

//     string result = web3->EthCall(&from, contractAddress, options.gas, gasPrice, &value, param);
//     return result;
// }
// string Contract::SendTransaction(uint32_t nonceVal, unsigned long long gasPriceVal, uint32_t gasLimitVal,
//                                string *toStr, string *valueStr, string *dataStr) {
//     static uint8_t signature[SIGNATURE_LENGTH];  // Make static to reduce stack usage
//     static int recid = 0;                       // Make static and single value instead of array
    
//     // Clear signature buffer
//     memset(signature, 0, SIGNATURE_LENGTH);
    
//     // Generate signature with static recid
//     GenerateSignature(signature, &recid, nonceVal, gasPriceVal, gasLimitVal,
//                      toStr, valueStr, dataStr);

//     // Use RlpEncodeForRawTransaction directly with web3->EthSendSignedTransaction
//     // to avoid storing the entire encoded transaction in memory
//     //vector<uint8_t> param = RlpEncodeForRawTransaction(nonceVal, gasPriceVal, gasLimitVal,
//     //                                                  toStr, valueStr, dataStr,
//     //                                                  signature, recid);

//     // Convert directly to string and send
//     //return web3->EthSendSignedTransaction(Util::VectorToString(param), param.size());

//     // Optimized RLP encoding
//     // uint8_t rlpEncoded[MAX_RLP_ENCODED_SIZE];
//     // size_t rlpEncodedLength = RlpEncodeForRawTransaction(nonceVal, gasPriceVal, gasLimitVal,
//     //                                                   toStr, valueStr, dataStr,
//     //                                                   signature, recid, rlpEncoded, MAX_RLP_ENCODED_SIZE);

//     if (rlpEncodedLength == 0) {
//         // Encoding failed
//         return "";
//     }

//     return web3->EthSendSignedTransaction(Util::ConvertBytesToHex((uint8_t*)rlpEncoded, rlpEncodedLength), rlpEncodedLength);
// }

#include <cstring>
#include <cstdlib>
#include <string>

// Предположим, что эти константы определены где-то в проекте
#define SIGNATURE_LENGTH 64
#define MAX_RLP_ENCODED_SIZE 512

// Вспомогательные функции для RLP-кодирования

// Преобразует число в минимальное big-endian представление.
// Записывает результат в buffer и возвращает количество байт.
static size_t intToBytes(uint64_t value, uint8_t *buffer) {
    size_t len = 0;
    uint64_t temp = value;
    while (temp) { temp >>= 8; len++; }
    if (len == 0) { len = 1; buffer[0] = 0; return 1; }
    for (size_t i = 0; i < len; i++) {
        buffer[len - 1 - i] = (uint8_t)(value >> (8 * i));
    }
    return len;
}

// Кодирует произвольный байтовый массив (data длины len) по RLP и записывает результат в dest.
// Возвращает общее число записанных байт.
static size_t encodeRlpItem(const uint8_t* data, size_t len, uint8_t* dest) {
    size_t index = 0;
    // Если это один байт меньше 0x80 – возвращаем его без префикса.
    if (len == 1 && data[0] < 0x80) {
        dest[index++] = data[0];
        return index;
    }
    if (len <= 55) {
        dest[index++] = 0x80 + len;
    } else {
        uint8_t lenBytes[8];
        size_t lenLen = intToBytes(len, lenBytes);
        dest[index++] = 0xB7 + lenLen;
        memcpy(dest + index, lenBytes, lenLen);
        index += lenLen;
    }
    memcpy(dest + index, data, len);
    index += len;
    return index;
}

// Кодирует число как RLP-элемент.
static size_t encodeRlpInteger(uint64_t value, uint8_t* dest) {
    if (value == 0) {
        // В RLP число 0 кодируется как пустая строка с префиксом 0x80.
        return encodeRlpItem((uint8_t*)"", 0, dest);
    }
    uint8_t intBytes[8];
    size_t intLen = intToBytes(value, intBytes);
    return encodeRlpItem(intBytes, intLen, dest);
}

// Удаляет ведущие нули из массива байт длины len, записывает результат в dest и возвращает новую длину.
static size_t trimZeros(const uint8_t* data, size_t len, uint8_t* dest) {
    size_t i = 0;
    while (i < len && data[i] == 0) i++;
    size_t newLen = (i < len) ? (len - i) : 0;
    memcpy(dest, data + i, newLen);
    return newLen;
}

// Функция RLP-кодирования подписанной транзакции.
// Поля:
// nonce, gasPrice, gasLimit – числовые значения.
// toStr, valueStr, dataStr – строки в hex-формате (с "0x").
// signature – 64-байтовый массив, где первые 32 байта – r, следующие 32 – s.
// recid – recovery id; v будет вычислено как (recid + 27).
// outBuffer – буфер для итогового RLP, maxSize – его размер.
// Возвращает длину итогового RLP-кода или 0 при ошибке.
static size_t RlpEncodeForRawTransaction(uint32_t nonce, uint64_t gasPrice, uint32_t gasLimit,
                                           const std::string *toStr, const std::string *valueStr, const std::string *dataStr,
                                           const uint8_t* signature, int recid,
                                           uint8_t* outBuffer, size_t maxSize) {
    uint8_t payload[512];
    size_t payloadLen = 0;
    uint8_t temp[128];
    size_t len = 0;

    // Кодирование nonce
    len = encodeRlpInteger(nonce, temp);
    memcpy(payload + payloadLen, temp, len); payloadLen += len;
    
    // Кодирование gasPrice
    len = encodeRlpInteger(gasPrice, temp);
    memcpy(payload + payloadLen, temp, len); payloadLen += len;
    
    // Кодирование gasLimit
    len = encodeRlpInteger(gasLimit, temp);
    memcpy(payload + payloadLen, temp, len); payloadLen += len;
    
    // Кодирование адреса (to)
    {
        const char* toHex = toStr->c_str();
        if (toHex[0]=='0' && (toHex[1]=='x' || toHex[1]=='X')) toHex += 2;
        size_t toHexLen = strlen(toHex);
        size_t toByteLen = toHexLen / 2;
        uint8_t toBytes[40];
        for (size_t i = 0; i < toByteLen; i++){
            char byteStr[3] = { toHex[i*2], toHex[i*2+1], 0 };
            toBytes[i] = (uint8_t) strtol(byteStr, NULL, 16);
        }
        len = encodeRlpItem(toBytes, toByteLen, temp);
        memcpy(payload + payloadLen, temp, len); payloadLen += len;
    }
    
    // Кодирование value
    {
        const char* valueHex = valueStr->c_str();
        if (valueHex[0]=='0' && (valueHex[1]=='x' || valueHex[1]=='X')) valueHex += 2;
        size_t valueHexLen = strlen(valueHex);
        size_t valueByteLen = valueHexLen / 2;
        uint8_t valueBytes[64];
        for (size_t i = 0; i < valueByteLen; i++){
            char byteStr[3] = { valueHex[i*2], valueHex[i*2+1], 0 };
            valueBytes[i] = (uint8_t) strtol(byteStr, NULL, 16);
        }
        len = encodeRlpItem(valueBytes, valueByteLen, temp);
        memcpy(payload + payloadLen, temp, len); payloadLen += len;
    }
    
    // Кодирование data
    {
        const char* dataHex = dataStr->c_str();
        if (dataHex[0]=='0' && (dataHex[1]=='x' || dataHex[1]=='X')) dataHex += 2;
        size_t dataHexLen = strlen(dataHex);
        size_t dataByteLen = dataHexLen / 2;
        uint8_t dataBytes[256];
        for (size_t i = 0; i < dataByteLen; i++){
            char byteStr[3] = { dataHex[i*2], dataHex[i*2+1], 0 };
            dataBytes[i] = (uint8_t) strtol(byteStr, NULL, 16);
        }
        len = encodeRlpItem(dataBytes, dataByteLen, temp);
        memcpy(payload + payloadLen, temp, len); payloadLen += len;
    }
    
    // Кодирование поля v (v = recid + 27)
    {
        uint64_t v = recid + 27;
        len = encodeRlpInteger(v, temp);
        memcpy(payload + payloadLen, temp, len); payloadLen += len;
    }
    
    // Кодирование поля r (первые 32 байта подписи, без ведущих нулей)
    {
        uint8_t rBytes[32];
        size_t rTrimmed = trimZeros(signature, 32, rBytes);
        len = encodeRlpItem(rBytes, rTrimmed, temp);
        memcpy(payload + payloadLen, temp, len); payloadLen += len;
    }
    
    // Кодирование поля s (следующие 32 байта подписи)
    {
        uint8_t sBytes[32];
        size_t sTrimmed = trimZeros(signature + 32, 32, sBytes);
        len = encodeRlpItem(sBytes, sTrimmed, temp);
        memcpy(payload + payloadLen, temp, len); payloadLen += len;
    }
    
    // Формирование RLP-списка из всех закодированных полей
    uint8_t header[16];
    size_t headerLen = 0;
    if (payloadLen <= 55) {
        header[0] = 0xC0 + payloadLen;
        headerLen = 1;
    } else {
        uint8_t lenBytes[8];
        size_t lenLen = intToBytes(payloadLen, lenBytes);
        header[0] = 0xF7 + lenLen;
        memcpy(header + 1, lenBytes, lenLen);
        headerLen = 1 + lenLen;
    }
    size_t totalLen = headerLen + payloadLen;
    if (totalLen > maxSize) return 0; // недостаточно места в буфере
    memcpy(outBuffer, header, headerLen);
    memcpy(outBuffer + headerLen, payload, payloadLen);
    return totalLen;
}

// Метод SendTransaction внутри класса Contract
std::string Contract::SendTransaction(uint32_t nonceVal, unsigned long long gasPriceVal, uint32_t gasLimitVal,
                                        std::string *toStr, std::string *valueStr, std::string *dataStr) {
    // Статические переменные для подписи – чтобы уменьшить расход стека.
    static uint8_t signature[SIGNATURE_LENGTH];
    static int recid = 0;
    
    // Обнуляем буфер подписи
    memset(signature, 0, SIGNATURE_LENGTH);
    
    // Генерируем подпись (функция должна заполнить signature и установить recid)
    GenerateSignature(signature, &recid, nonceVal, gasPriceVal, gasLimitVal, toStr, valueStr, dataStr);
    
    uint8_t rlpEncoded[MAX_RLP_ENCODED_SIZE];
    size_t rlpEncodedLength = RlpEncodeForRawTransaction(nonceVal, gasPriceVal, gasLimitVal,
                                                         toStr, valueStr, dataStr,
                                                         signature, recid,
                                                         rlpEncoded, MAX_RLP_ENCODED_SIZE);
    if (rlpEncodedLength == 0) {
        // Ошибка при кодировании
        return "";
    }
    
    // Преобразуем байты в hex-строку и отправляем транзакцию
    return web3->EthSendSignedTransaction("0x228", 3);
        // Util::ConvertBytesToHex(rlpEncoded, rlpEncodedLength), rlpEncodedLength);
}


/**
 * Private functions
 **/

void Contract::GenerateSignature(uint8_t *signature, int *recid, uint32_t nonceVal, unsigned long long gasPriceVal, uint32_t gasLimitVal,
                                 string *toStr, string *valueStr, string *dataStr)
{
    vector<uint8_t> encoded = RlpEncode(nonceVal, gasPriceVal, gasLimitVal, toStr, valueStr, dataStr);
    // hash
    string t = Util::VectorToString(encoded);

    uint8_t *hash = new uint8_t[ETHERS_KECCAK256_LENGTH];
    size_t encodedTxBytesLength = (t.length()-2)/2;
    uint8_t *bytes = new uint8_t[encodedTxBytesLength];
    Util::ConvertHexToBytes(bytes, t.c_str(), encodedTxBytesLength);

    Crypto::Keccak256((uint8_t*)bytes, encodedTxBytesLength, hash);

#if 0
    Serial.print("Digest: ");
    Serial.println(Util::ConvertBytesToHex(hash, ETHERS_KECCAK256_LENGTH).c_str());
#endif

    // sign
    Sign((uint8_t *)hash, signature, recid);

#if 0
    Serial.print("Sig: ");
    Serial.println(Util::ConvertBytesToHex(signature, SIGNATURE_LENGTH).c_str());
#endif
}

string Contract::GenerateContractBytes(const char *func)
{
    string in = "0x";
    char intmp[8];
    memset(intmp, 0, 8);

    for (int i = 0; i < 128; i++)
    {
        char c = func[i];
        if (c == '\0')
        {
            break;
        }
        sprintf(intmp, "%x", c);
        in = in + intmp;
    }
    //get the hash of the input
    string out = Crypto::Keccak256(Util::ConvertHexToVector(&in));
    out.resize(10);
    return out;
}

string Contract::GenerateBytesForUint(const uint32_t value)
{
    char output[70];
    memset(output, 0, sizeof(output));

    // check number of digits
    char dummy[64];
    int digits = sprintf(dummy, "%x", (uint32_t)value);

    // fill 0 and copy number to string
    for (int i = 2; i < 2 + 64 - digits; i++)
    {
        sprintf(output, "%s%s", output, "0");
    }
    sprintf(output, "%s%x", output, (uint32_t)value);
    return string(output);
}

string Contract::GenerateBytesForInt(const int32_t value)
{
    char output[70];
    memset(output, 0, sizeof(output));

    // check number of digits
    char dummy[64];
    int digits = sprintf(dummy, "%x", value);

    // fill 0 and copy number to string
    char fill[2];
    if (value >= 0)
    {
        sprintf(fill, "%s", "0");
    }
    else
    {
        sprintf(fill, "%s", "f");
    }
    for (int i = 2; i < 2 + 64 - digits; i++)
    {
        sprintf(output, "%s%s", output, fill);
    }
    sprintf(output, "%s%x", output, value);
    return string(output);
}

string Contract::GenerateBytesForUIntArray(const vector<uint32_t> *v)
{
    string output;
    char numstr[21];
    string dynamicMarker = "40";
    Util::PadForward(&dynamicMarker, 32);
    snprintf(numstr, sizeof(numstr), "%x", (unsigned int)v->size());
    string arraySize = numstr;
    Util::PadForward(&arraySize, 32);
    output = dynamicMarker + arraySize;
    for (auto itr = v->begin(); itr != v->end(); itr++)
    {
        snprintf(numstr, sizeof(numstr), "%x", (unsigned int)*itr);
        string element = numstr;
        Util::PadForward(&element, 32);
        output += element;
    }

    return output;
}

string Contract::GenerateBytesForAddress(const string *v)
{
    const char *value = v->c_str();
    size_t digits = strlen(value) - 2;

    string zeros = "";
    for (int i = 2; i < 2 + 64 - digits; i++)
    {
        zeros = zeros + "0";
    }
    return zeros + string(value + 2);
}

string Contract::GenerateBytesForString(const string *value)
{
    const char *valuePtr = value->c_str(); //don't fail if given a 'String'
    string zeros = "";
    size_t remain = 32 - ((strlen(valuePtr) - 2) % 32);
    for (int i = 0; i < remain + 32; i++)
    {
        zeros = zeros + "0";
    }

    return string(valuePtr + zeros);
}

string Contract::GenerateBytesForBytes(const char *value, const int len)
{
    char output[70];
    memset(output, 0, sizeof(output));

    for (int i = 0; i < len; i++)
    {
        sprintf(output, "%s%x", output, value[i]);
    }
    size_t remain = 32 - ((strlen(output) - 2) % 32);
    for (int i = 0; i < remain + 32; i++)
    {
        sprintf(output, "%s%s", output, "0");
    }

    return string(output);
}

vector<uint8_t> Contract::RlpEncode(
    uint32_t nonceVal, unsigned long long gasPriceVal, uint32_t gasLimitVal,
    string *toStr, string *valueStr, string *dataStr)
{
    vector<uint8_t> nonce = Util::ConvertNumberToVector(nonceVal);
    vector<uint8_t> gasPrice = Util::ConvertNumberToVector(gasPriceVal);
    vector<uint8_t> gasLimit = Util::ConvertNumberToVector(gasLimitVal);
    vector<uint8_t> to = Util::ConvertHexToVector(toStr);
    vector<uint8_t> value = Util::ConvertHexToVector(valueStr);
    vector<uint8_t> data = Util::ConvertHexToVector(dataStr);

    vector<uint8_t> outputNonce = Util::RlpEncodeItemWithVector(nonce);
    vector<uint8_t> outputGasPrice = Util::RlpEncodeItemWithVector(gasPrice);
    vector<uint8_t> outputGasLimit = Util::RlpEncodeItemWithVector(gasLimit);
    vector<uint8_t> outputTo = Util::RlpEncodeItemWithVector(to);
    vector<uint8_t> outputValue = Util::RlpEncodeItemWithVector(value);
    vector<uint8_t> outputData = Util::RlpEncodeItemWithVector(data);

    vector<uint8_t> encoded = Util::RlpEncodeWholeHeaderWithVector(
        outputNonce.size() +
        outputGasPrice.size() +
        outputGasLimit.size() +
        outputTo.size() +
        outputValue.size() +
        outputData.size());

    encoded.insert(encoded.end(), outputNonce.begin(), outputNonce.end());
    encoded.insert(encoded.end(), outputGasPrice.begin(), outputGasPrice.end());
    encoded.insert(encoded.end(), outputGasLimit.begin(), outputGasLimit.end());
    encoded.insert(encoded.end(), outputTo.begin(), outputTo.end());
    encoded.insert(encoded.end(), outputValue.begin(), outputValue.end());
    encoded.insert(encoded.end(), outputData.begin(), outputData.end());

#if 0
    Serial.println("RLP Encode:");
    Serial.println(Util::ConvertBytesToHex(encoded.data(), encoded.size()).c_str());
#endif

    return encoded;
}

void Contract::Sign(uint8_t *hash, uint8_t *sig, int *recid)
{
    BYTE fullSig[65];
    crypto->Sign(hash, fullSig);
    *recid = fullSig[64];
    memcpy(sig,fullSig, 64);
}

// Remove this function
#if 0
vector<uint8_t> Contract::RlpEncodeForRawTransaction(
    uint32_t nonceVal, unsigned long long gasPriceVal, uint32_t gasLimitVal,
    string *toStr, string *valueStr, string *dataStr, uint8_t *sig, uint8_t recid)
{

    vector<uint8_t> signature;
    for (int i = 0; i < SIGNATURE_LENGTH; i++)
    {
        signature.push_back(sig[i]);
    }
    vector<uint8_t> nonce = Util::ConvertNumberToVector(nonceVal);
    vector<uint8_t> gasPrice = Util::ConvertNumberToVector(gasPriceVal);
    vector<uint8_t> gasLimit = Util::ConvertNumberToVector(gasLimitVal);
    vector<uint8_t> to = Util::ConvertHexToVector(toStr);
    vector<uint8_t> value = Util::ConvertHexToVector(valueStr);
    vector<uint8_t> data = Util::ConvertHexToVector(dataStr);

    vector<uint8_t> outputNonce = Util::RlpEncodeItemWithVector(nonce);
    vector<uint8_t> outputGasPrice = Util::RlpEncodeItemWithVector(gasPrice);
    vector<uint8_t> outputGasLimit = Util::RlpEncodeItemWithVector(gasLimit);
    vector<uint8_t> outputTo = Util::RlpEncodeItemWithVector(to);
    vector<uint8_t> outputValue = Util::RlpEncodeItemWithVector(value);
    vector<uint8_t> outputData = Util::RlpEncodeItemWithVector(data);

    vector<uint8_t> R;
    R.insert(R.end(), signature.begin(), signature.begin()+(SIGNATURE_LENGTH/2));
    vector<uint8_t> S;
    S.insert(S.end(), signature.begin()+(SIGNATURE_LENGTH/2), signature.end());
    vector<uint8_t> V;
    V.push_back((uint8_t)(recid+27)); // 27 is a magic number for Ethereum spec
    vector<uint8_t> outputR = Util::RlpEncodeItemWithVector(R);
    vector<uint8_t> outputS = Util::RlpEncodeItemWithVector(S);
    vector<uint8_t> outputV = Util::RlpEncodeItemWithVector(V);

#if 0
    printf("\noutputNonce--------\n ");
    for (int i = 0; i<outputNonce.size(); i++) { printf("%02x ", outputNonce[i]); }
    printf("\noutputGasPrice--------\n ");
    for (int i = 0; i<outputGasPrice.size(); i++) {printf("%02x ", outputGasPrice[i]); }
    printf("\noutputGasLimit--------\n ");
    for (int i = 0; i<outputGasLimit.size(); i++) {printf("%02x ", outputGasLimit[i]); }
    printf("\noutputTo--------\n ");
    for (int i = 0; i<outputTo.size(); i++) {printf("%02x ", outputTo[i]); }
    printf("\noutputValue--------\n ");
    for (int i = 0; i<outputValue.size(); i++) { printf("%02x ", outputValue[i]); }
    printf("\noutputData--------\n ");
    for (int i = 0; i<outputData.size(); i++) { printf("%02x ", outputData[i]); }
    printf("\nR--------\n ");
    for (int i = 0; i<outputR.size(); i++) { printf("%02x ", outputR[i]); }
    printf("\nS--------\n ");
    for (int i = 0; i<outputS.size(); i++) { printf("%02x ", outputS[i]); }
    printf("\nV--------\n ");
    for (int i = 0; i<outputV.size(); i++) { printf("%02x ", outputV[i]); }
    printf("\n");
#endif

    vector<uint8_t> encoded = Util::RlpEncodeWholeHeaderWithVector(
        outputNonce.size() +
        outputGasPrice.size() +
        outputGasLimit.size() +
        outputTo.size() +
        outputValue.size() +
        outputData.size() +
        outputR.size() +
        outputS.size() +
        outputV.size());

    encoded.insert(encoded.end(), outputNonce.begin(), outputNonce.end());
    encoded.insert(encoded.end(), outputGasPrice.begin(), outputGasPrice.end());
    encoded.insert(encoded.end(), outputGasLimit.begin(), outputGasLimit.end());
    encoded.insert(encoded.end(), outputTo.begin(), outputTo.end());
    encoded.insert(encoded.end(), outputValue.begin(), outputValue.end());
    encoded.insert(encoded.end(), outputData.begin(), outputData.end());
    encoded.insert(encoded.end(), outputV.begin(), outputV.end());
    encoded.insert(encoded.end(), outputR.begin(), outputR.end());
    encoded.insert(encoded.end(), outputS.begin(), outputS.end());

    return encoded;
}
#endif

size_t Contract::RlpEncodeForRawTransaction(
    uint32_t nonceVal, unsigned long long gasPriceVal, uint32_t gasLimitVal,
    string *toStr, string *valueStr, string *dataStr, uint8_t *sig, uint8_t recid,
    uint8_t *outputBuffer, size_t bufferSize)
{
    // Calculate sizes
    size_t nonceSize = Util::GetNumberSize(nonceVal);
    size_t gasPriceSize = Util::GetNumberSize(gasPriceVal);
    size_t gasLimitSize = Util::GetNumberSize(gasLimitVal);
    size_t toSize = toStr->length() / 2;
    size_t valueSize = valueStr->length() / 2;
    size_t dataSize = dataStr->length() / 2;

    // Calculate total size
    size_t totalSize = 1 + // List header
                       Util::RlpEncodeItemSize(nonceSize) + nonceSize +
                       Util::RlpEncodeItemSize(gasPriceSize) + gasPriceSize +
                       Util::RlpEncodeItemSize(gasLimitSize) + gasLimitSize +
                       Util::RlpEncodeItemSize(toSize) + toSize +
                       Util::RlpEncodeItemSize(valueSize) + valueSize +
                       Util::RlpEncodeItemSize(dataSize) + dataSize +
                       Util::RlpEncodeItemSize(SIGNATURE_LENGTH / 2) + SIGNATURE_LENGTH / 2 + // R
                       Util::RlpEncodeItemSize(SIGNATURE_LENGTH / 2) + SIGNATURE_LENGTH / 2 + // S
                       Util::RlpEncodeItemSize(1) + 1; // V

    if (totalSize > bufferSize) {
        // Buffer is too small
        return 0;
    }

    size_t offset = 0;

    // List header
    offset += Util::RlpEncodeListHeader(totalSize - 1, outputBuffer + offset, bufferSize - offset);

    // Encode items
    uint8_t nonceBytes[8];
    size_t nonceLen = intToBytes(nonceVal, nonceBytes);
    offset += Util::RlpEncodeItem(outputBuffer + offset, nonceBytes, nonceLen);

    uint8_t gasPriceBytes[8];
    size_t gasPriceLen = intToBytes(gasPriceVal, gasPriceBytes);
    offset += Util::RlpEncodeItem(outputBuffer + offset, gasPriceBytes, gasPriceLen);

    uint8_t gasLimitBytes[8];
    size_t gasLimitLen = intToBytes(gasLimitVal, gasLimitBytes);
    offset += Util::RlpEncodeItem(outputBuffer + offset, gasLimitBytes, gasLimitLen);

    offset += Util::RlpEncodeItem(outputBuffer + offset, (const uint8_t*)toStr->c_str(), toStr->length());
    offset += Util::RlpEncodeItem(outputBuffer + offset, (const uint8_t*)valueStr->c_str(), valueStr->length());
    offset += Util::RlpEncodeItem(outputBuffer + offset, (const uint8_t*)dataStr->c_str(), dataStr->length());

    // Encode V, R, S
    outputBuffer[offset++] = recid + 27;

    memcpy(outputBuffer + offset, sig, SIGNATURE_LENGTH);
    offset += SIGNATURE_LENGTH;

    return totalSize;
}
