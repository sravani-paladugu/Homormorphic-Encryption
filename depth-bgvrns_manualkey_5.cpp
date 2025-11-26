#include "openfhe.h"
#include <iostream>
#include <vector>
#include <cstdlib> // For std::srand
#include <limits>  // For std::numeric_limits

using namespace lbcrypto;

int main() {
    // =================================================================
    // 1. SETUP THE CRYPTO CONTEXT (The "Lock" / Parameter Definition)
    // =================================================================
    CCParams<CryptoContextBGVRNS> parameters;
    parameters.SetMultiplicativeDepth(3);
    parameters.SetPlaintextModulus(536903681); // A large prime modulus
    parameters.SetMaxRelinSkDeg(3); 

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
    
    // Enable necessary features
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);
    
    std::cout << "HE Context Initialized for BGV-RNS (Depth 3).\n";

    // =================================================================
    // 2. GENERATE KEYS (The Keys / Trust Setup)
    // =================================================================
    
    // --- START USER INPUT FOR KEY GENERATION ---
    int userSeed;
    std::cout << "\nEnter an integer for key generation ";
    if (!(std::cin >> userSeed)) {
        std::cerr << "Invalid input received. Using default seed 1337." << std::endl;
        userSeed = 1337;
        // Clear cin buffer in case of failure
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    }
    
    // Use the user input to seed the standard random number generator. 
    // This makes the keys deterministic based on the input seed.
    std::srand(userSeed); 
    
    // Generate the Public Key (for encryption) and Secret Key (for decryption)
    KeyPair<DCRTPoly> keyPair = cryptoContext->KeyGen();

    // Generate the Evaluation/Multiplication Key (REQUIRED for EvalMult)
    // This is the expensive step.
    cryptoContext->EvalMultKeysGen(keyPair.secretKey);
    
    std::cout << "Keys Generated (Public, Secret, and Multiplication Keys) using seed: " << userSeed << ".\n";

    // =================================================================
    // 3. ENCRYPT DATA
    // =================================================================
    std::vector<int64_t> vector1 = {5, 6, 7, 8};
    std::vector<int64_t> vector2 = {2, 3, 4, 5};

    // Encode the integer vectors into BGV-RNS plaintext polynomials
    Plaintext plaintext1 = cryptoContext->MakePackedPlaintext(vector1);
    Plaintext plaintext2 = cryptoContext->MakePackedPlaintext(vector2);

    // Encrypt using the Public Key
    auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
    auto ciphertext2 = cryptoContext->Encrypt(keyPair.publicKey, plaintext2);

    std::cout << "\nInputs Encrypted:\n";
    std::cout << "Input 1: " << plaintext1 << std::endl;
    std::cout << "Input 2: " << plaintext2 << std::endl;


    // =================================================================
    // 4. COMPUTE HOMOMORPHICALLY (The Server Operation)
    // =================================================================
    // The server performs multiplication on the ciphertexts without decrypting them.
    // This step automatically uses the Evaluation/Multiplication Key generated above.
    auto ciphertextMult = cryptoContext->EvalMult(ciphertext1, ciphertext2);
    
    std::cout << "Homomorphic Multiplication (EvalMult) Complete.\n";

    // =================================================================
    // 5. DECRYPT RESULT
    // =================================================================
    Plaintext result;
    // Decrypt using the Secret Key
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextMult, &result);

    // Output
    result->SetLength(vector1.size());
    std::cout << "\nDecrypted Result: " << result << std::endl;
    std::cout << "Expected Result (5*2, 6*3, 7*4, 8*5): [10, 18, 28, 40]\n";

    return 0;
}
