**OpenFHE BGV-RNS Examples:** **Depth 3 Homomorphic Operations**

This repository contains three C++ examples demonstrating core concepts of the BGV-RNS (Brakerski-Gentry-Vaikuntanathan) scheme with Residue Number System (RNS) in the OpenFHE library.
All examples are configured for a multiplicative depth of 3, meaning they support up to three sequential multiplications on encrypted data.
________________________________________
 **File 1: depth-bgvrns_manualkey_2.cpp** (Comprehensive Key Loading and Computation)
This file demonstrates the advanced process of serialization and deserialization for all required cryptographic keys to perform a complete homomorphic operation in a fresh context. 
This simulates a secure environment where keys are generated externally and then provided to a computing server.

**Key Purpose & Method**
This file's primary purpose is to prove that a full homomorphic multiplication can be successfully executed using keys that were entirely loaded from their string representations, 
not generated internally within the running program's context.

•	It shows how to generate and save the string representations for the Public Key, Secret Key, and Evaluation/Multiplication Key.

•	The program then clears any internal keys and loads these three keys back from the strings using Serial::Deserialize and cryptoContext->DeserializeEvalMultKey.

•	It then executes a full Encrypt->EvalMult->Decrypt cycle using the loaded keys.

**Brief Code Explanation**
•	The code explicitly generates all three key types and serializes them into separate std::string variables (MY_PUBLIC_KEY, MY_SECRET_KEY, MY_MULT_KEY).

•	The call to cryptoContext->ClearEvalMultKeys(); ensures that the subsequent computation is entirely dependent on the successful deserialization of the Multiplication Key via cryptoContext->DeserializeEvalMultKey(ssMK, SerType::JSON);.

•	The final operation is homomorphic multiplication of vectors ([1, 2, 3, 4]).([10, 11, 12, 13])$, resulting in the decrypted output [10, 22, 36, 52].
________________________________________
**File 2: depth-bgvrns_manualkey_3.cpp** (Single Secret Key Transfer)
This file focuses on the fundamental concept of serialization and deserialization as applied to a single cryptographic object: the Secret Key. 
This process is vital for storing keys securely or transferring them to a decryption authority.
 **Key Purpose & Method**
This file demonstrates the ability to load a pre-generated Secret Key from its string representation to perform a decryption. This is a crucial, lower-level step often required in key management.

•	A temporary Secret Key is generated and converted (serialized) into a single, long std::string (MANUAL_SECRET_KEY_STRING).

•	The main logic focuses on successfully converting this string back into a functional Secret Key object using Serial::Deserialize.

•	The file uses the loaded key to successfully decrypt a ciphertext that was encrypted with the corresponding Public Key.

**Brief Code Explanation**

•	The key is converted to a string using Serial::Serialize(tempKeyPair.secretKey, skStream, SerType::JSON);.

•	The key is loaded back into the loadedKeyPair.secretKey object via Serial::Deserialize(loadedKeyPair.secretKey, inputStream, SerType::JSON);.

•	The core validation is the successful decryption using the manually loaded key: cryptoContext->Decrypt(loadedKeyPair.secretKey, ciphertext, &result);.
________________________________________
 **File 3: depth-bgvrns_manualkey_5.cpp**  (Core Homomorphic Encryption Workflow)
This file represents the standard, end-to-end homomorphic encryption workflow used to demonstrate the fundamental capability of performing mathematical operations on encrypted data.

**Key Purpose & Method**

This file demonstrates the full Homomorphic Encryption lifecycle where the keys are generated and used within a single execution context to perform secure multiplication.
1.	Context Setup: Defines the secure BGV-RNS parameters (depth 3, modulus $536903681).
2.	Key Generation: Creates the Public Key (for encryption), Secret Key (for decryption), and the Evaluation Key (for homomorphic multiplication).
3.	Encrypted Computation: Performs multiplication (EvalMult) on two ciphertexts.
4.	Decryption: Recovers the plaintext result using the Secret Key.

 **Brief Code Explanation**
 
•	The keys are generated in one step: KeyPair<DCRTPoly> keyPair = cryptoContext->KeyGen();.

•	The critical step for enabling multiplication is cryptoContext->EvalMultKeysGen(keyPair.secretKey);.

•	The homomorphic operation is performed by auto ciphertextMult = cryptoContext->EvalMult(ciphertext1, ciphertext2);.

•	The example demonstrates element-wise multiplication: ([5, 6, 7, 8]).([2, 3, 4, 5]), yielding the expected decrypted result [10, 18, 28, 40].
________________________________________
**File 4: key_management.h (The Interface)**
This file acts as the public interface (like a header file) for the key management module. It tells the rest of the application (specifically depth-bgvrns_manualkey_6.cpp) exactly what functions are available and what data they use, without revealing the implementation details.

**Content: **Contains only the declarations (prototypes) for the functions.

**Key Functions:**

KeyPair<DCRTPoly> GenerateKeys(CryptoContext<DCRTPoly> context)

void SerializeKeys(CryptoContext<DCRTPoly> context, const KeyPair<DCRTPoly>& keyPair)

 **File 5. key_management.cpp (The Key Server/Offline Process)**
This file contains the implementation of the key management logic. It represents the secure, offline process where a trusted party generates the necessary cryptographic keys.

**Key Functions:**

**GenerateKeys**: This function calls context->KeyGen() and context->EvalMultKeysGen() to create the Public Key, Secret Key, and Evaluation Keys (needed for homomorphic multiplication).

**SerializeKeys**: This function saves all the generated keys to disk files using OpenFHE's serialization features. This is how the keys are transferred (in a real-world scenario, securely) to the application environment.

         secret_key.json

         public_key.json

         mult_key.json

**File 6: depth-bgvrns_manualkey_6.cpp (The Main Application/Client)**
This is the main executable file containing the main() function. It separates the execution into two distinct phases: Key Generation/Serialization (using the imported functions) and Application Execution.

**Key Generation Phase** (Offline/Simulation):

It calls SetupContext() to define the HE parameters. It calls the external functions: GenerateKeys() and SerializeKeys().

**Application Phase** (Online):

It performs Deserialization (loading) of the keys from the disk files (simulating the client receiving keys).

It uses the loaded Public Key for Encryption.

It uses the loaded Evaluation Keys implicitly during the homomorphic computation (EvalMult).

It uses the loaded Secret Key for Decryption to reveal the result.
