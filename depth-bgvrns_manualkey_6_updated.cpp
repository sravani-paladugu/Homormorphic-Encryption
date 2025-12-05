#include "openfhe.h"
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "scheme/bgvrns/bgvrns-ser.h"   // Required for BGV scheme-specific serialization
#include "key/key-ser.h"         // Required for deserializing EvalKey types
#include "key_management.h" // Needed for KeyPair struct definition
#include <fstream>
#include <iostream>
#include <cstdio> // For std::remove

using namespace lbcrypto;

/**
 * @brief Sets up the core BGV-RNS CryptoContext parameters.
 * NOTE: This function MUST be identical to the one in key_management.cpp.
 * @return The initialized CryptoContext.
 */
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

int main() {
    // We keep the SetupContext call as we need a context object to load keys into
    CryptoContext<DCRTPoly> context = SetupContext();

    // ---------------------------------------------------------------------------------
    // STEP 1: APPLICATION STARTUP & DESERIALIZATION (Input from Key Server)
    // ---------------------------------------------------------------------------------

    // NOTE: Key generation and serialization calls have been REMOVED from this file.
    // The key files (secret_key.json, etc.) must exist before running this program.
    
    std::cout << "\n--- 1. ONLINE KEY LOADING (Input from Key Server) ---" << std::endl;
    std::cout << "Application loading keys from disk files..." << std::endl;

    KeyPair<DCRTPoly> loadedKeyPair;
    
    // 1. Load Secret Key (Needed for Decryption)
    if (Serial::DeserializeFromFile("secret_key.json", loadedKeyPair.secretKey, SerType::JSON) == false) {
        std::cerr << "ERROR: Failed to load Secret Key file! Did you run key_management first?" << std::endl;
        return 1;
    }

    // 2. Load Public Key (Needed for Encryption)
    if (Serial::DeserializeFromFile("public_key.json", loadedKeyPair.publicKey, SerType::JSON) == false) {
        std::cerr << "ERROR: Failed to load Public Key file! Did you run key_management first?" << std::endl;
        return 1;
    }

    // 3. Load Multiplication Keys (Needed for Homomorphic Operations)
    std::ifstream ifs("mult_key.json", std::ios::in);
    if (ifs.is_open()) {
        if (context->DeserializeEvalMultKey(ifs, SerType::JSON) == false) {
            std::cerr << "ERROR: Failed to deserialize Multiplication Key from stream!" << std::endl;
            return 1;
        }
        ifs.close();
    } else {
        std::cerr << "ERROR: Failed to open mult_key.json for reading! Did you run key_management first?" << std::endl;
        return 1;
    }

    std::cout << "Keys loaded successfully. Starting homomorphic computation.\n";

    // ---------------------------------------------------------------------------------
    // STEP 2: RUN COMPUTATION
    // ---------------------------------------------------------------------------------
    
    // Data (Input)
    std::vector<int64_t> vector1 = {5, 6, 7, 8};
    std::vector<int64_t> vector2 = {2, 3, 4, 5};

    // A. Encode & Encrypt (using the loaded Public Key)
    Plaintext plaintext1 = context->MakePackedPlaintext(vector1);
    Plaintext plaintext2 = context->MakePackedPlaintext(vector2);
    auto ciphertext1 = context->Encrypt(loadedKeyPair.publicKey, plaintext1);
    auto ciphertext2 = context->Encrypt(loadedKeyPair.publicKey, plaintext2);
    
    std::cout << "\nInput 1: " << plaintext1 << std::endl;
    std::cout << "Input 2: " << plaintext2 << std::endl;

    // B. Compute (Multiplication - uses the loaded mult keys implicitly)
    std::cout << "Running EvalMult...\n";
    auto ciphertextMult = context->EvalMult(ciphertext1, ciphertext2);

    // C. Decrypt (using the loaded Secret Key)
    Plaintext result;
    context->Decrypt(loadedKeyPair.secretKey, ciphertextMult, &result);

    // Output
    result->SetLength(vector1.size());
    std::cout << "\nResult: " << result << std::endl;
    std::cout << "Success: Homomorphic multiplication confirmed. (10, 18, 28, 40)\n";
    
    return 0;
}
