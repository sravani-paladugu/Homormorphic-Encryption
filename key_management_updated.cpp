#include "openfhe.h"
#include "cryptocontext-ser.h"
#include "scheme/bgvrns/bgvrns-ser.h"   // Required for BGV scheme-specific serialization
#include "key/key-ser.h"
#include "key_management.h" 
#include <iostream>
#include <fstream> // Required for std::ofstream

using namespace lbcrypto;

// --- Context Setup (Required for the standalone executable) ---
CryptoContext<DCRTPoly> SetupContext() {
    CCParams<CryptoContextBGVRNS> parameters;
    parameters.SetMultiplicativeDepth(3);
    parameters.SetPlaintextModulus(536903681);
    parameters.SetMaxRelinSkDeg(3); 

    CryptoContext<DCRTPoly> context = GenCryptoContext(parameters);
    context->Enable(PKE);
    context->Enable(KEYSWITCH);
    context->Enable(LEVELEDSHE);
    
    return context;
}
// -------------------------------------------------------------


// --- Implementation of GenerateKeys ---
KeyPair<DCRTPoly> GenerateKeys(CryptoContext<DCRTPoly> context) {
    std::cout << "Generating keys (Public, Secret, and Evaluation Keys)..." << std::endl;
    KeyPair<DCRTPoly> keyPair = context->KeyGen();
    context->EvalMultKeysGen(keyPair.secretKey);
    return keyPair;
}

// --- Implementation of SerializeKeys (FIXED FOR std::ofstream ERROR) ---
void SerializeKeys(CryptoContext<DCRTPoly> context, const KeyPair<DCRTPoly>& keyPair) {
    std::cout << "Serializing keys to files..." << std::endl;
    
    // Serialize Context
    Serial::SerializeToFile("cryptocontext.json", context, SerType::JSON);
    
    // Serialize Keys
    if (Serial::SerializeToFile("secret_key.json", keyPair.secretKey, SerType::JSON) == false) {
        std::cerr << "Error writing secret_key.json" << std::endl;
    }
    if (Serial::SerializeToFile("public_key.json", keyPair.publicKey, SerType::JSON) == false) {
        std::cerr << "Error writing public_key.json" << std::endl;
    }
    
    // FIX: Use std::ofstream to explicitly open the output stream for EvalMultKey
    std::ofstream ofs("mult_key.json", std::ios::out);
    if (!ofs.is_open()) {
        std::cerr << "Error: Could not open mult_key.json for writing!" << std::endl;
    } else {
        if (context->SerializeEvalMultKey(ofs, SerType::JSON) == false) {
             std::cerr << "Error writing mult_key.json" << std::endl;
        }
        ofs.close();
    }
}
// ---------------------------------------


// --- MAIN FUNCTION ---
int main() {
    std::cout << "=================================================================\n";
    std::cout << "  KEY MANAGEMENT SERVER: GENERATING AND SERIALIZING KEYS\n";
    std::cout << "=================================================================\n";

    // 1. Setup the Context
    CryptoContext<DCRTPoly> generation_context = SetupContext();
    
    // 2. Generate and Serialize Keys 
    KeyPair<DCRTPoly> generatedKeyPair = GenerateKeys(generation_context);
    SerializeKeys(generation_context, generatedKeyPair);

    std::cout << "SUCCESS: Keys serialized to disk (secret_key.json, etc.).\n";
    return 0;
}
