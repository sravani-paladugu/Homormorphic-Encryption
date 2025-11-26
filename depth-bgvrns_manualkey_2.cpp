#include "openfhe.h"
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/bgvrns/bgvrns-ser.h"
#include <sstream>

using namespace lbcrypto;

int main() {
    // =================================================================================
    // 1. SETUP THE CONTEXT (The "Lock")
    //    These parameters MUST match the parameters used to generate the manual key.
    // =================================================================================
    CCParams<CryptoContextBGVRNS> parameters;
    parameters.SetMultiplicativeDepth(3);
    parameters.SetPlaintextModulus(536903681);
    parameters.SetMaxRelinSkDeg(3);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);

    std::cout << "Context Initialized.\n";
    std::cout << "p (Plaintext Modulus) = " << parameters.GetPlaintextModulus() << std::endl;

    // =================================================================================
    // 2. GENERATE RAW STRINGS (Simulating you copying a key from a file)
    // =================================================================================
    std::cout << "\n--- Generating Key Strings (Simulating External Input) ---" << std::endl;
    
    // Generate keys temporarily just to turn them into strings
    KeyPair<DCRTPoly> tempKeyPair = cryptoContext->KeyGen();
    cryptoContext->EvalMultKeysGen(tempKeyPair.secretKey);

    std::stringstream skStream, pkStream, mkStream;
    Serial::Serialize(tempKeyPair.secretKey, skStream, SerType::JSON);
    Serial::Serialize(tempKeyPair.publicKey, pkStream, SerType::JSON);
    cryptoContext->SerializeEvalMultKey(mkStream, SerType::JSON);

    // Store them in string variables (This represents your "Manual Input")
    std::string MY_SECRET_KEY = skStream.str();
    std::string MY_PUBLIC_KEY = pkStream.str();
    std::string MY_MULT_KEY   = mkStream.str();

    // PRINT THE KEY TO SEE IT
    std::cout << "\n[VISUAL CHECK] Here is a snippet of your Secret Key:\n";
    std::cout << MY_SECRET_KEY.substr(0, 200) << "...\n(truncated for readability)\n";

    // CLEANUP: Wipe the context's internal memory to prove we are loading fresh
    cryptoContext->ClearEvalMultKeys(); 

    // =================================================================================
    // 3. LOAD MANUAL KEYS (The "Key")
    // =================================================================================
    std::cout << "\n--- Loading Manual Keys into Context ---" << std::endl;

    KeyPair<DCRTPoly> loadedKeyPair;

    // A. Load Secret Key
    std::stringstream ssSK(MY_SECRET_KEY);
    Serial::Deserialize(loadedKeyPair.secretKey, ssSK, SerType::JSON);
    
    // B. Load Public Key
    std::stringstream ssPK(MY_PUBLIC_KEY);
    Serial::Deserialize(loadedKeyPair.publicKey, ssPK, SerType::JSON);

    // C. Load Multiplication Key (Required for math operations)
    std::stringstream ssMK(MY_MULT_KEY);
    cryptoContext->DeserializeEvalMultKey(ssMK, SerType::JSON);

    if(!loadedKeyPair.secretKey) {
        std::cerr << "Error: Secret Key is empty!" << std::endl;
        return 1;
    }
    std::cout << "Success: All keys loaded manually.\n";

    // =================================================================================
    // 4. RUN THE PROGRAM
    // =================================================================================
    
    // Inputs
    std::vector<int64_t> vector1 = {1, 2, 3, 4};
    std::vector<int64_t> vector2 = {10, 11, 12, 13};

    // Encode
    Plaintext plaintext1 = cryptoContext->MakePackedPlaintext(vector1);
    Plaintext plaintext2 = cryptoContext->MakePackedPlaintext(vector2);

    // Encrypt (Using the Loaded Public Key)
    std::cout << "\n--- Encrypting Data ---" << std::endl;
    auto ciphertext1 = cryptoContext->Encrypt(loadedKeyPair.publicKey, plaintext1);
    auto ciphertext2 = cryptoContext->Encrypt(loadedKeyPair.publicKey, plaintext2);

    // Compute (Multiply) - This uses the loaded Multiplication Key internally
    std::cout << "--- Multiplying Ciphertexts (Homomorphic Operation) ---" << std::endl;
    auto ciphertextMult = cryptoContext->EvalMult(ciphertext1, ciphertext2);

    // Decrypt (Using the Loaded Secret Key)
    std::cout << "--- Decrypting Result ---" << std::endl;
    Plaintext result;
    cryptoContext->Decrypt(loadedKeyPair.secretKey, ciphertextMult, &result);

    // Output
    result->SetLength(4);
    std::cout << "Input 1: " << plaintext1 << std::endl;
    std::cout << "Input 2: " << plaintext2 << std::endl;
    std::cout << "Result : " << result << std::endl;

    return 0;
}
