/*
 *  ghash.h
 *
 *  Copyright (C) 2024
 *  Terrapane Corporation
 *  All Rights Reserved
 *
 *  Author:
 *      Paul E. Jones <paulej@packetizer.com>
 *
 *  Description:
 *      This file defines the Galois Counter Mode (GCM) Hashing (GHASH) object
 *      that implements the logic defined in NIST Special Publication 800-38D.
 *
 *      This may be used stand-alone to produce a hash value from a stream of
 *      octets, though it is generally used only by the GCM object.
 *
 *      Since the GHASH function operates on blocks of 16 octets at a time,
 *      performance is greatly improved if either all AAD or text input is
 *      provided at the outset or provided in multiples of 16 octets.
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

#include <span>
#include <cstdint>
#include <terra/secutil/secure_array.h>
#include <terra/secutil/secure_vector.h>

namespace Terra::Crypto::Cipher
{

// Define the GHASH object
class GHASH
{
    public:
        // Maximum length of AAD (2^64 - 1 bits) in octets
        static constexpr std::uint64_t Max_AAD_Octets = 0x1fff'ffff'ffff'ffff;

        // Maximum length of the plaintext or ciphertext (2^39 - 256 bits)
        // expressed in terms of octets
        static constexpr std::size_t Max_Input_Octets = 0x0000'000f'ffff'ffe0;

        GHASH(const std::span<const std::uint8_t, 16> H);
        GHASH(const std::span<const std::uint8_t, 16> H,
              const std::span<const std::uint8_t> aad,
              const std::span<const std::uint8_t> text);
        ~GHASH();

        void InputAAD(const std::span<const std::uint8_t> aad);
        void InputText(const std::span<const std::uint8_t> text);
        void Finalize();
        void Result(std::span<std::uint8_t, 16> result);
        void Result(std::span<std::uint32_t, 4> result);

    protected:
        void ConsumeInput(const std::span<const std::uint8_t> text);
        void ProcessResidualInput();
        void MultiplyGF(std::span<std::uint32_t, 4> X,
                        std::span<const std::uint32_t, 4> Y);

        bool aad_complete;
        bool finalized;
        std::uint64_t aad_length;
        std::uint64_t text_length;
        SecUtil::SecureVector<std::uint8_t> remaining_input;
        SecUtil::SecureArray<std::uint32_t, 4> T;
        SecUtil::SecureArray<std::uint32_t, 4> H;
        SecUtil::SecureArray<std::uint32_t, 4> Y;
};

} // namespace Terra::Crypto::Cipher
