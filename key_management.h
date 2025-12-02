#ifndef KEY_MANAGEMENT_H
#define KEY_MANAGEMENT_H

#include "openfhe.h"

using namespace lbcrypto;

/**
 * @brief Generates the Public, Secret, and Evaluation Keys.
 * @param context The configured CryptoContext.
 * @return The generated KeyPair.
 */
KeyPair<DCRTPoly> GenerateKeys(CryptoContext<DCRTPoly> context);

/**
 * @brief Serializes the generated keys and saves them to disk files.
 * @param context The configured CryptoContext (needed for EvalMultKey serialization).
 * @param keyPair The generated KeyPair containing Public and Secret Keys.
 */
void SerializeKeys(CryptoContext<DCRTPoly> context, const KeyPair<DCRTPoly>& keyPair);

#endif // KEY_MANAGEMENT_H
