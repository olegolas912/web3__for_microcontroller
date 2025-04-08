//
// Created by Okada, Takahiro on 2018/02/04.
//

#ifndef ARDUINO_WEB3_WEB3_H
#define ARDUINO_WEB3_WEB3_H

typedef unsigned char BYTE;
#define ETHERS_PRIVATEKEY_LENGTH       32
#define ETHERS_PUBLICKEY_LENGTH        64
#define ETHERS_ADDRESS_LENGTH          20
#define ETHERS_KECCAK256_LENGTH        32
#define ETHERS_SIGNATURE_LENGTH        65

#include "stdint.h"
#include <string>

class Web3 {
public:
    Web3(const char* _host, const char* _path);
    //std::string Web3ClientVersion();
    //std::string Web3Sha3(const std::string* data);
    //int NetVersion();
    //bool NetListening();
    //int NetPeerCount();
    //double EthProtocolVersion();
    //bool EthSyncing();
    //bool EthMining();
    //double EthHashrate();
    //long long int EthGasPrice();
    //void EthAccounts(char** array, int size);
    //int EthBlockNumber();
    //long long int EthGetBalance(const std::string* address);
    int EthGetTransactionCount(const std::string* address);
    //std::string EthGetDeployedContractAddress(const std::string* transaction);
    //std::string EthViewCall(const std::string* data, const char* to);

    //std::string EthCall(const std::string* from, const char* to, long gas, long gasPrice, const std::string* value, const std::string* data);
    std::string EthSendSignedTransaction(const std::string& data, const uint32_t dataLen);

    long long int getLongLong(const std::string* json);
    std::string getString(const std::string* json);
    int getInt(const std::string* json);

private:
    std::string exec(const std::string* data);
    std::string generateJson(const std::string* method, const std::string* params);
    
    long getLong(const std::string* json);
    double getDouble(const std::string* json);
    bool getBool(const std::string* json);

private:
    const char* host;
    const char* path;
};

#endif //ARDUINO_WEB3_WEB3_H
