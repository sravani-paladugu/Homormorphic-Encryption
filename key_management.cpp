#include "key_management.h"
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/bgvrns/bgvrns-ser.h"
#include <fstream>
#include <iostream>

using namespace lbcrypto;

KeyPair<DCRTPoly> GenerateKeys(CryptoContext<DCRTPoly> context) {
    std::cout << "\n--- 1. OFFLINE KEY GENERATION ---" << std::endl;
    std::cout << "Generating KeyPair and Evaluation Keys..." << std::endl;
    
    // Generate KeyPair and Evaluation Keys
    KeyPair<DCRTPoly> keyPair = context->KeyGen();
    context->EvalMultKeysGen(keyPair.secretKey);

    std::cout << "Keys generated successfully.\n";
    return keyPair;
}

void SerializeKeys(CryptoContext<DCRTPoly> context, const KeyPair<DCRTPoly>& keyPair) {
    std::cout << "\n--- 2. KEY SERIALIZATION & SAVING ---" << std::endl;
    std::cout << "Saving keys to disk files..." << std::endl;
    
    // 1. Save Secret Key (Needed for Decryption)
    if (Serial::SerializeToFile("secret_key.json", keyPair.secretKey, SerType::JSON) == false) {
        std::cerr << "Error writing secret key to file!" << std::endl;
    }

    // 2. Save Public Key (Needed for Encryption)
    if (Serial::SerializeToFile("public_key.json", keyPair.publicKey, SerType::JSON) == false) {
        std::cerr << "Error writing public key to file!" << std::endl;
    }

    // 3. Save Evaluation (Multiplication) Keys (Needed for homomorphic multiply)
    std::ofstream ofs("mult_key.json", std::ios::out);
    if (ofs.is_open()) {
        if (context->SerializeEvalMultKey(ofs, SerType::JSON) == false) {
            std::cerr << "Error writing multiplication keys to stream!" << std::endl;
        }
        ofs.close();
    } else {
        std::cerr << "Error opening mult_key.json for writing!" << std::endl;
    }
    
    // Critical: Clear the stored keys after serialization to prove loading works
    context->ClearEvalMultKeys();

    std::cout << "Keys successfully saved: secret_key.json, public_key.json, mult_key.json\n";
}
