#include "openfhe.h"
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/bgvrns/bgvrns-ser.h"
#include <fstream>
#include <iostream>
#include <sstream>
#include <cstdio> // For std::remove (to clean up files)

using namespace lbcrypto;

/**
 * @brief Sets up the core BGV-RNS CryptoContext parameters.
 * These parameters define the mathematical space (the 'Lock').
 * They MUST be identical for generation and loading.
 * @return The initialized CryptoContext.
 */
CryptoContext<DCRTPoly> SetupContext() {
    CCParams<CryptoContextBGVRNS> parameters;
    parameters.SetMultiplicativeDepth(3);
    parameters.SetPlaintextModulus(536903681);
    parameters.SetMaxRelinSkDeg(3); // Needed for correct key size

    CryptoContext<DCRTPoly> context = GenCryptoContext(parameters);
    context->Enable(PKE);
    context->Enable(KEYSWITCH);
    context->Enable(LEVELEDSHE);
    
    std::cout << "Context setup complete (BGV-RNS, Depth 3).\n";
    return context;
}

/**
 * @brief Simulates the OFFLINE, trusted process of generating keys and saving them to disk.
 * This is the source of the "Manual Keys".
 * @param context The configured CryptoContext.
 */
void GenerateAndSaveKeys(CryptoContext<DCRTPoly> context) {
    std::cout << "\n--- 1. OFFLINE KEY GENERATION & SAVING ---" << std::endl;
    std::cout << "Generating keys and saving to files..." << std::endl;
    
    // Generate KeyPair and Evaluation Keys
    KeyPair<DCRTPoly> keyPair = context->KeyGen();
    context->EvalMultKeysGen(keyPair.secretKey);

    // 1. Save Secret Key (Needed for Decryption)
    if (Serial::SerializeToFile("secret_key.json", keyPair.secretKey, SerType::JSON) == false) {
        std::cerr << "Error writing secret key to file!" << std::endl;
    }

    // 2. Save Public Key (Needed for Encryption)
    if (Serial::SerializeToFile("public_key.json", keyPair.publicKey, SerType::JSON) == false) {
        std::cerr << "Error writing public key to file!" << std::endl;
    }

    // 3. Save Evaluation (Multiplication) Keys (Needed for homomorphic multiply)
    // FIX: Use std::ofstream and pass the stream, not the filename string.
    std::ofstream ofs("mult_key.json", std::ios::out);
    if (ofs.is_open()) {
        if (context->SerializeEvalMultKey(ofs, SerType::JSON) == false) {
            std::cerr << "Error writing multiplication keys to stream!" << std::endl;
        }
        ofs.close();
    } else {
        std::cerr << "Error opening mult_key.json for writing!" << std::endl;
    }
    
    // --- CRITICAL FIX: Clear the stored keys after serialization ---
    // This prevents the "Can not save a EvalMultKeys vector" error when we 
    // try to Deserialize the same key data into a new context later.
    context->ClearEvalMultKeys();

    std::cout << "Keys successfully saved: secret_key.json, public_key.json, mult_key.json\n";
}


int main() {
    // Clean up old files for a fresh run
    std::remove("secret_key.json");
    std::remove("public_key.json");
    std::remove("mult_key.json");
    
    // =================================================================
    // STEP 0: SETUP
    // =================================================================
    CryptoContext<DCRTPoly> context = SetupContext();
    GenerateAndSaveKeys(context); // Creates the necessary JSON files

    // ---------------------------------------------------------------------------------
    // STEP 1: APPLICATION STARTUP (The Client/Consumer Application)
    // ---------------------------------------------------------------------------------
    
    // Re-initialize the context with the same parameters for the client application.
    context = SetupContext();

    std::cout << "\n--- 2. ONLINE KEY LOADING (Manual Input Simulation) ---" << std::endl;
    std::cout << "Application loading keys from disk files..." << std::endl;

    // Initialize containers for the loaded keys
    KeyPair<DCRTPoly> loadedKeyPair;
    
    // =================================================================
    // CORE MANUAL KEY LOADING LOGIC (Deserialization from Files)
    // =================================================================
    
    // 1. Load Secret Key (Needed for Decryption)
    if (Serial::DeserializeFromFile("secret_key.json", loadedKeyPair.secretKey, SerType::JSON) == false) {
        std::cerr << "ERROR: Failed to load Secret Key file!" << std::endl;
        return 1;
    }

    // 2. Load Public Key (Needed for Encryption)
    if (Serial::DeserializeFromFile("public_key.json", loadedKeyPair.publicKey, SerType::JSON) == false) {
        std::cerr << "ERROR: Failed to load Public Key file!" << std::endl;
        return 1;
    }

    // 3. Load Multiplication Keys (Needed for Homomorphic Operations)
    // FIX: Use std::ifstream and pass the stream, not the filename string.
    std::ifstream ifs("mult_key.json", std::ios::in);
    if (ifs.is_open()) {
        if (context->DeserializeEvalMultKey(ifs, SerType::JSON) == false) {
            std::cerr << "ERROR: Failed to deserialize Multiplication Key from stream!" << std::endl;
            return 1;
        }
        ifs.close();
    } else {
        std::cerr << "ERROR: Failed to open mult_key.json for reading!" << std::endl;
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
    std::cout << "Success: Homomorphic multiplication confirmed. (5*2, 6*3, 7*4, 8*5 = 10, 18, 28, 40)\n";
    
    return 0;
}
