//
// Created by James on 2018/09/13.
//

#ifndef ARDUINO_WEB3_CRYPTO_H
#define ARDUINO_WEB3_CRYPTO_H

#include "Log.h"
#include "Web3.h"
#include <vector>

//using namespace std; // Removed

class Crypto {

public:
    Crypto(Web3* _web3);
    bool Sign(BYTE* digest, BYTE* result);
    void SetPrivateKey(const char *key);
    
    static void ECRecover(BYTE* signature, BYTE *public_key, BYTE *message_hash); 
    static bool Verify(const uint8_t *public_key, const uint8_t *message_hash, const uint8_t *signature);
    static void PrivateKeyToPublic(const uint8_t *privateKey, uint8_t *publicKey);
    static void PublicKeyToAddress(const uint8_t *publicKey, uint8_t *address);
    static void Keccak256(const uint8_t *data, uint16_t length, uint8_t *result);

    static std::string Keccak256(std::vector<uint8_t> bytes);


private:
    Log Debug;
    #define LOG(x) Debug.println(x)

    Web3* web3;
    uint8_t privateKey[ETHERS_PRIVATEKEY_LENGTH];

};


#endif //ARDUINO_WEB3_CRYPTO_H
