/*
 *  ghash.cpp
 *
 *  Copyright (C) 2024
 *  Terrapane Corporation
 *  All Rights Reserved
 *
 *  Author:
 *      Paul E. Jones <paulej@packetizer.com>
 *
 *  Description:
 *      This file implements the Galois Counter Mode (GCM) Hash object that
 *      is defined in NIST Special Publication 800-38D.
 *
 *      The specification describes operations on bit strings.  For performance
 *      reasons, internally this implementation groups the bits into 32-bit
 *      words.  This reduces the number of bit shift and XOR operations
 *      required.
 *
 *  Portability Issues:
 *      None.
 */

#include <cstring>
#include <terra/crypto/cipher/gcm.h>
#include <terra/crypto/cipher/ghash.h>
#include <terra/secutil/secure_erase.h>
#include "gcm_utilities.h"

namespace Terra::Crypto::Cipher
{

/*
 *  GHASH::GHASH()
 *
 *  Description:
 *      Constructor for the GHASH object.
 *
 *  Parameters:
 *      H [in]
 *          The value of H as per Section 6.4 of NIST SP 800-38D.
 *
 *  Returns:
 *      Nothing.
 *
 *  Comments:
 *      None.
 */
GHASH::GHASH(const std::span<const std::uint8_t, 16> H) :
    aad_complete{false},
    finalized{false},
    aad_length{0},
    text_length{0},
    H{},
    Y{}
{
    GetWordArray(H, this->H);
}

/*
 *  GHASH::GHASH()
 *
 *  Description:
 *      Constructor for the GHASH object that will perform the initialization,
 *      handle any AAD, process input text, and finalize the hash all in one
 *      step.  One only needs to call the Result() function to retrieve the
 *      resulting hash value.
 *
 *  Parameters:
 *      H [in]
 *          The value of H as per Section 6.4 of NIST SP 800-38D.
 *
 *      aad [in]
 *          Additional authenticated data (AAD) to be provided as input.
 *
 *      text [in]
 *          Plaintext or ciphertext to be consumed by the GHASH function.
 *
 *  Returns:
 *      Nothing.
 *
 *  Comments:
 *      None.
 */
GHASH::GHASH(const std::span<const std::uint8_t, 16> H,
             const std::span<const std::uint8_t> aad,
             const std::span<const std::uint8_t> text) :
    GHASH(H)
{
    InputAAD(aad);
    InputText(text);
    Finalize();
}

/*
 *  GHASH::~GHASH()
 *
 *  Description:
 *      Destructor for the GHASH object.
 *
 *  Parameters:
 *      None.
 *
 *  Returns:
 *      Nothing.
 *
 *  Comments:
 *      None.
 */
GHASH::~GHASH()
{
    // For security reasons, zero all internal data that does not securely
    // clear themselves
    SecUtil::SecureErase(aad_complete);
    SecUtil::SecureErase(finalized);
    SecUtil::SecureErase(aad_length);
    SecUtil::SecureErase(text_length);
}

/*
 *  GHASH::InputAAD()
 *
 *  Description:
 *      Additional authenticated data (AAD) to be consumed by the GHASH object.
 *      Providing AAD is optional, but if it is provided it MUST be provided
 *      before providing plaintext or ciphertext (i.e., before calling
 *      InputText())
 *
 *  Parameters:
 *      aad [in]
 *          Additional authenticated data (AAD) to be provided as input.
 *          For best performance, the length of the span should be an
 *          integral number of 16 octets, with the exception of the last block.
 *          One may call this function multiple times to provide AAD to the
 *          hashing function incrementally.
 *
 *  Returns:
 *      Nothing.
 *
 *  Comments:
 *      The maximum length of AAD per the specification is 2^64 - 1 bits.
 */
void GHASH::InputAAD(const std::span<const std::uint8_t> aad)
{
    // Was it believed that AAD input was complete?
    if (aad_complete) throw GCMException("AAD received out-of-order");

    // Was the hashing operation already finalized?
    if (finalized) throw GCMException("Hash already finalized");

    // Do no processing if the length is zero
    if (aad.empty()) return;

    // Consume the input
    ConsumeInput(aad);

    // Update the AAD length
    if ((aad_length + aad.size() <= aad_length) ||
        ((aad_length + aad.size()) > Max_AAD_Octets))
    {
        throw GCMException("Maximum AAD input length exceeded");
    }

    // Update the AAD length
    aad_length += aad.size();
}

/*
 *  GHASH::InputText()
 *
 *  Description:
 *      Plaintext or ciphertext to be consumed by the GHASH object.  This
 *      should be called after any AAD is inputted.
 *
 *  Parameters:
 *      text [in]
 *          Plaintext or ciphertext to be consumed by the GHASH function.
 *          For best performance, the length of the span should be an
 *          integral number of 16 octets, with the exception of the last block.
 *          One may call this function multiple times to provide text to the
 *          hashing function incrementally.
 *
 *  Returns:
 *      Nothing.
 *
 *  Comments:
 *      The maximum text length per the specification is 2^39 - 256 bits.
 */
void GHASH::InputText(const std::span<const std::uint8_t> text)
{
    // Was the hashing operation already finalized?
    if (finalized) throw GCMException("Hash already finalized");

    // Are we done processing AAD?
    if (!aad_complete)
    {
        // Process any residual data
        ProcessResidualInput();

        // Note that AAD input is complete
        aad_complete = true;
    }

    // If there is no data to consume, return
    if (text.empty()) return;

    // Consume the input
    ConsumeInput(text);

    // Update input text length
    if ((text_length + text.size() <= text_length) ||
        ((text_length + text.size()) > Max_Input_Octets))
    {
        throw GCMException("Maximum text input length exceeded");
    }

    // Update the text length
    text_length += text.size();
}

/*
 *  GHASH::Finalize()
 *
 *  Description:
 *      Once all input is provided to the GHASH function, this function is
 *      called to signify that no additional data will be provided.
 *
 *  Parameters:
 *      None.
 *
 *  Returns:
 *      Nothing.
 *
 *  Comments:
 *      None.
 */
void GHASH::Finalize()
{
    // Was the hashing operation already finalized?
    if (finalized) throw GCMException("Hash already finalized");

    // Process any residual data
    ProcessResidualInput();

    // Note the hashing operation is finalized
    finalized = true;

    // Final operation uses the AAD and text lengths as bit lengths
    aad_length <<= 3;
    text_length <<= 3;

    // Re-use remaining_input as a temporary buffer
    remaining_input.resize(16);

    // Place the AAD length into the buffer
    remaining_input[ 0] = (aad_length >> 56) & 0xff;
    remaining_input[ 1] = (aad_length >> 48) & 0xff;
    remaining_input[ 2] = (aad_length >> 40) & 0xff;
    remaining_input[ 3] = (aad_length >> 32) & 0xff;
    remaining_input[ 4] = (aad_length >> 24) & 0xff;
    remaining_input[ 5] = (aad_length >> 16) & 0xff;
    remaining_input[ 6] = (aad_length >>  8) & 0xff;
    remaining_input[ 7] = (aad_length      ) & 0xff;

    remaining_input[ 8] = (text_length >> 56) & 0xff;
    remaining_input[ 9] = (text_length >> 48) & 0xff;
    remaining_input[10] = (text_length >> 40) & 0xff;
    remaining_input[11] = (text_length >> 32) & 0xff;
    remaining_input[12] = (text_length >> 24) & 0xff;
    remaining_input[13] = (text_length >> 16) & 0xff;
    remaining_input[14] = (text_length >>  8) & 0xff;
    remaining_input[15] = (text_length      ) & 0xff;

    // Process the remaining_input vector
    ProcessResidualInput();
}

/*
 *  GHASH::Result()
 *
 *  Description:
 *      Retrieves a copy of the result of the GHASH operation.
 *
 *  Parameters:
 *      result [out]
 *          A span into which the hash result will be written.
 *
 *  Returns:
 *      Nothing, though the output parameter result will be populated.
 *
 *  Comments:
 *      None.
 */
void GHASH::Result(std::span<std::uint8_t, 16> result)
{
    // Ensure the GHASH is finalized
    if (!finalized) throw GCMException("Hash is not finalized");

    // Copy the value of Y into result
    PutWordArray(Y, result);
}

/*
 *  GHASH::Result()
 *
 *  Description:
 *      Retrieves a copy of the result of the GHASH operation.
 *
 *  Parameters:
 *      result [out]
 *          A span into which the hash result will be written.
 *
 *  Returns:
 *      Nothing, though the output parameter result will be populated.
 *
 *  Comments:
 *      None.
 */
void GHASH::Result(std::span<std::uint32_t, 4> result)
{
    // Ensure the GHASH is finalized
    if (!finalized) throw GCMException("Hash is not finalized");

    // Copy the value of Yi into result
    std::memcpy(result.data(), Y.data(), result.size_bytes());
}

/*
 *  GHASH::ConsumeInput()
 *
 *  Description:
 *      This function will consume the input to be hashed.  The logic for
 *      consumption of AAD and plaintext or ciphertext is the same.  Thus,
 *      those input functions call this routine to handle the addition
 *      and multiplication operations on the input.
 *
 *  Parameters:
 *      input [in]
 *          Input to be consumed by the hashing function.
 *
 *  Returns:
 *      Nothing.
 *
 *  Comments:
 *      None.
 */
void GHASH::ConsumeInput(const std::span<const std::uint8_t> text)
{
    // How many octets remaining
    std::size_t remaining = text.size();

    // Do nothing if there is no data
    if (remaining == 0) return;

    // Octets consumed from "text"
    std::size_t consumed = 0;

    // Is there prior partial input?
    if (!remaining_input.empty())
    {
        consumed =
            std::min(static_cast<std::size_t>(16) - remaining_input.size(),
                     text.size());
        remaining_input.insert(remaining_input.end(),
                               text.data(),
                               text.data() + consumed);

        // If there is only a partial block, just return
        if (remaining_input.size() < 16) return;

        // Place the octets into the word array
        GetWordArray(std::span<const std::uint8_t, 16>(remaining_input.data(),
                                                       remaining_input.size()),
                     T);

        // Determine the number of octets remaining as input
        remaining -= consumed;

        // Yi XOR Ai
        VectorXOR(Y, T);

        // Multiply Yi x H
        MultiplyGF(Y, H);

        // Clear the remaining input buffer
        remaining_input.clear();
    }

    // Iterate over the text in complete blocks
    while (remaining >= 16)
    {
        // Place the octets into the word array
        GetWordArray(std::span<const std::uint8_t, 16>(text.data() + consumed,
                                                       16),
                     T);

        // Yi+1 = Yi XOR A_i (or C_i)
        VectorXOR(Y, T);

        // Adjust the count of remaining and consumed octets
        remaining -= 16;
        consumed += 16;

        // Multiply Yi+1 = Yi x H
        MultiplyGF(Y, H);
    }

    // If there are any residual octets, just store them
    if (remaining > 0)
    {
        remaining_input.insert(remaining_input.end(),
                               text.data() + consumed,
                               text.data() + consumed + remaining);
    }
}

/*
 *  GHASH::ProcessResidualInput()
 *
 *  Description:
 *      This function will consume the residual input in the remaining_input
 *      vector.  This is called after AAD is inputted and when finalizing
 *      the hashing operation.
 *
 *  Parameters:
 *      None.
 *
 *  Returns:
 *      Nothing.
 *
 *  Comments:
 *      The maximum text length per the specification is 2^39 - 256 bits.
 */
void GHASH::ProcessResidualInput()
{
    // Is there any residual input to process?
    if (!remaining_input.empty())
    {
        // Pad remaining_input with zeros to length 16
        remaining_input.resize(16, 0);

        // Place the octets into the word array
        GetWordArray(std::span<const std::uint8_t, 16>(remaining_input.data(),
                                                       16),
                     T);

        // Yi+1 = Yi XOR A_i (or C_i)
        VectorXOR(Y, T);

        // Multiply Yi+1 = Yi x H
        MultiplyGF(Y, H);

        // Clear the remaining_input
        remaining_input.clear();
    }
}

/*
 *  GHASH::MultiplySingleTerm()
 *
 *  Description:
 *      This function will handle the work of multiplying a single term
 *      in the polynomial as per Algorithm 1 in Section 6.3 of
 *      NIST SP 800-38D.
 *
 *  Parameters:
 *      index [in]
 *          The index into the vector Y on which to operate.
 *
 *      bit [in]
 *          The target bit to inspect.
 *
 *      T [in]
 *          The vector T, which holds the original X that is being operated on.
 *
 *      X [in]
 *          The vector X, which will ultimately hold the output.
 *
 *      Y [in]
 *          The vector Y against which the original X is multiplied.
 *
 *  Returns:
 *      Nothing, though T and X are updated.
 *
 *  Comments:
 *      None.
 */
constexpr void MultiplySingleTerm(std::size_t index,
                                  std::uint32_t bit,
                                  std::span<std::uint32_t, 4> T,
                                  std::span<std::uint32_t, 4> X,
                                  std::span<const std::uint32_t, 4> Y)
{
    // Constant used for polynomial division
    constexpr std::uint32_t Divisor_R32 = 0xe100'0000;

    // If the target bit Y[i] is 1, X = X XOR T
    if ((Y[index] & bit) != 0) VectorXOR(X, T);

    // Bit 127 determines a shift or both shift and perform modulo division
    if ((T[3] & 0x0000'0001) == 0)
    {
        // Right-shift vector T
        VectorRightShift(T);
    }
    else
    {
        // Right-shift vector T
        VectorRightShift(T);

        // If we need to take the modulo, T = T XOR R
        T[0] ^= Divisor_R32;
    }
}

/*
 *  GHASH::MultiplyGF()
 *
 *  Description:
 *      Perform a multiplication operation per the GCM specification in
 *      Galois Field GF(2^128).  That is, implements X = X * Y.
 *
 *  Parameters:
 *      X [in]
 *          First input value used in a multiplication operation.
 *
 *      Y [in]
 *          Second input value used in a multiplication operation.
 *
 *  Returns:
 *      Nothing, though the output will be stored in X.
 *
 *  Comments:
 *      The code to perform the iteration over the terms Y could be written
 *      using a for() loop and be made much more readable. However, loops are
 *      slower and this unrolled version is substantially faster, even when
 *      compiling optimized code.
 */
void GHASH::MultiplyGF(std::span<std::uint32_t, 4> X,
                       std::span<const std::uint32_t, 4> Y)
{
    // Copy the value of X into T
    std::memcpy(T.data(), X.data(), X.size_bytes());

    // Zero X
    std::memset(X.data(), 0, X.size_bytes());

    // Operator over each term
    MultiplySingleTerm(0, 0x8000'0000, T, X, Y);
    MultiplySingleTerm(0, 0x4000'0000, T, X, Y);
    MultiplySingleTerm(0, 0x2000'0000, T, X, Y);
    MultiplySingleTerm(0, 0x1000'0000, T, X, Y);
    MultiplySingleTerm(0, 0x0800'0000, T, X, Y);
    MultiplySingleTerm(0, 0x0400'0000, T, X, Y);
    MultiplySingleTerm(0, 0x0200'0000, T, X, Y);
    MultiplySingleTerm(0, 0x0100'0000, T, X, Y);
    MultiplySingleTerm(0, 0x0080'0000, T, X, Y);
    MultiplySingleTerm(0, 0x0040'0000, T, X, Y);
    MultiplySingleTerm(0, 0x0020'0000, T, X, Y);
    MultiplySingleTerm(0, 0x0010'0000, T, X, Y);
    MultiplySingleTerm(0, 0x0008'0000, T, X, Y);
    MultiplySingleTerm(0, 0x0004'0000, T, X, Y);
    MultiplySingleTerm(0, 0x0002'0000, T, X, Y);
    MultiplySingleTerm(0, 0x0001'0000, T, X, Y);
    MultiplySingleTerm(0, 0x0000'8000, T, X, Y);
    MultiplySingleTerm(0, 0x0000'4000, T, X, Y);
    MultiplySingleTerm(0, 0x0000'2000, T, X, Y);
    MultiplySingleTerm(0, 0x0000'1000, T, X, Y);
    MultiplySingleTerm(0, 0x0000'0800, T, X, Y);
    MultiplySingleTerm(0, 0x0000'0400, T, X, Y);
    MultiplySingleTerm(0, 0x0000'0200, T, X, Y);
    MultiplySingleTerm(0, 0x0000'0100, T, X, Y);
    MultiplySingleTerm(0, 0x0000'0080, T, X, Y);
    MultiplySingleTerm(0, 0x0000'0040, T, X, Y);
    MultiplySingleTerm(0, 0x0000'0020, T, X, Y);
    MultiplySingleTerm(0, 0x0000'0010, T, X, Y);
    MultiplySingleTerm(0, 0x0000'0008, T, X, Y);
    MultiplySingleTerm(0, 0x0000'0004, T, X, Y);
    MultiplySingleTerm(0, 0x0000'0002, T, X, Y);
    MultiplySingleTerm(0, 0x0000'0001, T, X, Y);

    MultiplySingleTerm(1, 0x8000'0000, T, X, Y);
    MultiplySingleTerm(1, 0x4000'0000, T, X, Y);
    MultiplySingleTerm(1, 0x2000'0000, T, X, Y);
    MultiplySingleTerm(1, 0x1000'0000, T, X, Y);
    MultiplySingleTerm(1, 0x0800'0000, T, X, Y);
    MultiplySingleTerm(1, 0x0400'0000, T, X, Y);
    MultiplySingleTerm(1, 0x0200'0000, T, X, Y);
    MultiplySingleTerm(1, 0x0100'0000, T, X, Y);
    MultiplySingleTerm(1, 0x0080'0000, T, X, Y);
    MultiplySingleTerm(1, 0x0040'0000, T, X, Y);
    MultiplySingleTerm(1, 0x0020'0000, T, X, Y);
    MultiplySingleTerm(1, 0x0010'0000, T, X, Y);
    MultiplySingleTerm(1, 0x0008'0000, T, X, Y);
    MultiplySingleTerm(1, 0x0004'0000, T, X, Y);
    MultiplySingleTerm(1, 0x0002'0000, T, X, Y);
    MultiplySingleTerm(1, 0x0001'0000, T, X, Y);
    MultiplySingleTerm(1, 0x0000'8000, T, X, Y);
    MultiplySingleTerm(1, 0x0000'4000, T, X, Y);
    MultiplySingleTerm(1, 0x0000'2000, T, X, Y);
    MultiplySingleTerm(1, 0x0000'1000, T, X, Y);
    MultiplySingleTerm(1, 0x0000'0800, T, X, Y);
    MultiplySingleTerm(1, 0x0000'0400, T, X, Y);
    MultiplySingleTerm(1, 0x0000'0200, T, X, Y);
    MultiplySingleTerm(1, 0x0000'0100, T, X, Y);
    MultiplySingleTerm(1, 0x0000'0080, T, X, Y);
    MultiplySingleTerm(1, 0x0000'0040, T, X, Y);
    MultiplySingleTerm(1, 0x0000'0020, T, X, Y);
    MultiplySingleTerm(1, 0x0000'0010, T, X, Y);
    MultiplySingleTerm(1, 0x0000'0008, T, X, Y);
    MultiplySingleTerm(1, 0x0000'0004, T, X, Y);
    MultiplySingleTerm(1, 0x0000'0002, T, X, Y);
    MultiplySingleTerm(1, 0x0000'0001, T, X, Y);

    MultiplySingleTerm(2, 0x8000'0000, T, X, Y);
    MultiplySingleTerm(2, 0x4000'0000, T, X, Y);
    MultiplySingleTerm(2, 0x2000'0000, T, X, Y);
    MultiplySingleTerm(2, 0x1000'0000, T, X, Y);
    MultiplySingleTerm(2, 0x0800'0000, T, X, Y);
    MultiplySingleTerm(2, 0x0400'0000, T, X, Y);
    MultiplySingleTerm(2, 0x0200'0000, T, X, Y);
    MultiplySingleTerm(2, 0x0100'0000, T, X, Y);
    MultiplySingleTerm(2, 0x0080'0000, T, X, Y);
    MultiplySingleTerm(2, 0x0040'0000, T, X, Y);
    MultiplySingleTerm(2, 0x0020'0000, T, X, Y);
    MultiplySingleTerm(2, 0x0010'0000, T, X, Y);
    MultiplySingleTerm(2, 0x0008'0000, T, X, Y);
    MultiplySingleTerm(2, 0x0004'0000, T, X, Y);
    MultiplySingleTerm(2, 0x0002'0000, T, X, Y);
    MultiplySingleTerm(2, 0x0001'0000, T, X, Y);
    MultiplySingleTerm(2, 0x0000'8000, T, X, Y);
    MultiplySingleTerm(2, 0x0000'4000, T, X, Y);
    MultiplySingleTerm(2, 0x0000'2000, T, X, Y);
    MultiplySingleTerm(2, 0x0000'1000, T, X, Y);
    MultiplySingleTerm(2, 0x0000'0800, T, X, Y);
    MultiplySingleTerm(2, 0x0000'0400, T, X, Y);
    MultiplySingleTerm(2, 0x0000'0200, T, X, Y);
    MultiplySingleTerm(2, 0x0000'0100, T, X, Y);
    MultiplySingleTerm(2, 0x0000'0080, T, X, Y);
    MultiplySingleTerm(2, 0x0000'0040, T, X, Y);
    MultiplySingleTerm(2, 0x0000'0020, T, X, Y);
    MultiplySingleTerm(2, 0x0000'0010, T, X, Y);
    MultiplySingleTerm(2, 0x0000'0008, T, X, Y);
    MultiplySingleTerm(2, 0x0000'0004, T, X, Y);
    MultiplySingleTerm(2, 0x0000'0002, T, X, Y);
    MultiplySingleTerm(2, 0x0000'0001, T, X, Y);

    MultiplySingleTerm(3, 0x8000'0000, T, X, Y);
    MultiplySingleTerm(3, 0x4000'0000, T, X, Y);
    MultiplySingleTerm(3, 0x2000'0000, T, X, Y);
    MultiplySingleTerm(3, 0x1000'0000, T, X, Y);
    MultiplySingleTerm(3, 0x0800'0000, T, X, Y);
    MultiplySingleTerm(3, 0x0400'0000, T, X, Y);
    MultiplySingleTerm(3, 0x0200'0000, T, X, Y);
    MultiplySingleTerm(3, 0x0100'0000, T, X, Y);
    MultiplySingleTerm(3, 0x0080'0000, T, X, Y);
    MultiplySingleTerm(3, 0x0040'0000, T, X, Y);
    MultiplySingleTerm(3, 0x0020'0000, T, X, Y);
    MultiplySingleTerm(3, 0x0010'0000, T, X, Y);
    MultiplySingleTerm(3, 0x0008'0000, T, X, Y);
    MultiplySingleTerm(3, 0x0004'0000, T, X, Y);
    MultiplySingleTerm(3, 0x0002'0000, T, X, Y);
    MultiplySingleTerm(3, 0x0001'0000, T, X, Y);
    MultiplySingleTerm(3, 0x0000'8000, T, X, Y);
    MultiplySingleTerm(3, 0x0000'4000, T, X, Y);
    MultiplySingleTerm(3, 0x0000'2000, T, X, Y);
    MultiplySingleTerm(3, 0x0000'1000, T, X, Y);
    MultiplySingleTerm(3, 0x0000'0800, T, X, Y);
    MultiplySingleTerm(3, 0x0000'0400, T, X, Y);
    MultiplySingleTerm(3, 0x0000'0200, T, X, Y);
    MultiplySingleTerm(3, 0x0000'0100, T, X, Y);
    MultiplySingleTerm(3, 0x0000'0080, T, X, Y);
    MultiplySingleTerm(3, 0x0000'0040, T, X, Y);
    MultiplySingleTerm(3, 0x0000'0020, T, X, Y);
    MultiplySingleTerm(3, 0x0000'0010, T, X, Y);
    MultiplySingleTerm(3, 0x0000'0008, T, X, Y);
    MultiplySingleTerm(3, 0x0000'0004, T, X, Y);
    MultiplySingleTerm(3, 0x0000'0002, T, X, Y);
    MultiplySingleTerm(3, 0x0000'0001, T, X, Y);
}

} // namespace Terra::Crypto::Cipher
