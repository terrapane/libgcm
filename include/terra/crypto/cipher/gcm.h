/*
 *  gcm.h
 *
 *  Copyright (C) 2024
 *  Terrapane Corporation
 *  All Rights Reserved
 *
 *  Author:
 *      Paul E. Jones <paulej@packetizer.com>
 *
 *  Description:
 *      This file defines the Galois Counter Mode (GCM) object that
 *      implements the logic defined in NIST Special Publication 800-38D.
 *
 *      To utilize this object, one must first set the key and initialization
 *      vector (IV, also referred to as a nonce).
 *
 *      Once the key and IV are set, the InputAAD() function is called to
 *      provide all of the additional authenticated data to the GCM object.
 *      Since AAD might not exist as a contiguous chunk of memory, this function
 *      may be called multiple times to provide all of the data.  The only
 *      requirement is that all data be provided in order and before Encrypt()
 *      or Decrypt() is called.  This function cannot be called once Encrypt()
 *      or Decrypt() is called, as that would lead to incorrect results.
 *
 *      To optimize performance, Additional Authenticated Data (AAD) should be
 *      provided in multiples of 16 octets, though the final block may
 *      necessarily have fewer.
 *
 *      One then calls Encrypt() or Decrypt() (but do not mix modes!) with
 *      data to be encrypted or decrypted.  Since GCM uses a 128-bit block
 *      cipher for encryption, each call to Encrypt() or Decrypt() MUST contain
 *      a multiple of 16 octets except for the final input which may have fewer.
 *      These functions will perform encryption or decryption immediately and
 *      return the result in the output parameter.  One MAY use the same
 *      buffer for both input and output when calling Encrypt() or Decrypt().
 *
 *      After all of the plaintext or ciphertext has been inputted into GCM,
 *      one calls FinalizeAndGetTag() when encrypting or
 *      FinalizeAndVerifyTag() when decrypting.
 *
 *      NIST Special Publication 800-38D says the GCM tag may be any of the bit
 *      lengths 128, 120, 112, 104, or 96.  However, some applications may use
 *      even shorter tags.  Truncation of the tag is left to the user.
 *
 *      The specification states that the maximum input lengths are as follows:
 *          - Plaintext / Ciphertext : 0 .. 2^39 - 256 bits
 *          - AAD - 0 .. 2^64 - 1 bits
 *          - IV - 1 .. 2^64 -1 bits
 *
 *      If these limits are exceeded, an exception will be thrown when passing
 *      input.  The GCM object will verify the IV length is not exceeded, while
 *      the GHASH object will verify the AAD and text lengths are not exceeded.
 *
 *  Portability Issues:
 *      None.
 */

#pragma once

#include <stdexcept>
#include <span>
#include <cstdint>
#include <limits>
#include <memory>
#include <terra/secutil/secure_array.h>
#include <terra/crypto/cipher/aes.h>
#include "ghash.h"

namespace Terra::Crypto::Cipher
{

// Define an exception class for GCM-related exceptions
class GCMException : public std::runtime_error
{
    using std::runtime_error::runtime_error;
};

// Define the cipher types that can be used with GCM (only AES is supported)
enum class BlockCipher
{
    AES
};

// Define the Galois Counter Mode (GCM) object
class GCM
{
    public:
        // The maximum length of the IV (2^64 - 1 bits) in octets
        static constexpr std::uint64_t Max_IV_Length = 0x1fff'ffff'ffff'ffff;

        // Maximum number of 128-bit blocks that may be encrypted / decrypted
        static constexpr std::size_t Max_Input_Blocks = 0xffff'fffe;

        GCM(BlockCipher cipher = BlockCipher::AES);
        GCM(const std::span<const std::uint8_t> iv,
            const std::span<const std::uint8_t> key,
            BlockCipher cipher = BlockCipher::AES);
        GCM(const GCM &other);
        GCM(GCM &&other);
        virtual ~GCM();

        GCM &operator=(const GCM &other);

        void SetKey(const std::span<const std::uint8_t> iv,
                    const std::span<const std::uint8_t> key);

        void InputAAD(const std::span<const std::uint8_t> aad);

        std::span<std::uint8_t> Encrypt(
            const std::span<const std::uint8_t> plaintext,
            std::span<std::uint8_t> ciphertext);

        std::span<std::uint8_t> Decrypt(
            const std::span<const std::uint8_t> ciphertext,
            std::span<std::uint8_t> plaintext);

        void FinalizeAndGetTag(std::span<std::uint8_t, 16> tag);

        bool FinalizeAndVerifyTag(const std::span<const std::uint8_t> tag);

    protected:
        bool finalized;
        bool final_text;
        std::uint32_t counter;
        AES aes;
        SecUtil::SecureArray<std::uint8_t, 16> H;
        SecUtil::SecureArray<std::uint8_t, 16> Y0;
        SecUtil::SecureArray<std::uint8_t, 16> Y;
        SecUtil::SecureArray<std::uint8_t, 16> T1;
        SecUtil::SecureArray<std::uint8_t, 16> T2;
        SecUtil::SecureArray<std::uint32_t, 4> W1;
        SecUtil::SecureArray<std::uint32_t, 4> W2;
        std::unique_ptr<GHASH> ghash;
};

} // namespace Terra::Crypto::Cipher
