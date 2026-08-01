/*
 *  ghash.cpp
 *
 *  Copyright (C) 2024, 2026
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
#include <cstddef>
#include <cstdint>
#include <span>
#include <algorithm>
#ifndef TERRA_DISABLE_GHASH_TABLES
#include <array>
#endif // TERRA_DISABLE_GHASH_TABLES
#include <terra/secutil/secure_array.h>
#include <terra/crypto/cipher/gcm.h>
#include <terra/crypto/cipher/ghash.h>
#include <terra/secutil/secure_erase.h>
#include "gcm_utilities.h"

namespace Terra::Crypto::Cipher::GCM
{

namespace
{

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
    const bool reduce = (T[3] & 1U) != 0;

    // Right-shift vector T
    VectorRightShift(T);

    // If we need to take the modulo, T = T XOR R
    if (reduce) T[0] ^= Divisor_R32;
}

#ifndef TERRA_DISABLE_GHASH_TABLES

/*
 *  MakeReductionTable()
 *
 *  Description:
 *      In Galois/Counter Mode (GCM), multiplication in GF(2^128) uses the
 *      reduction polynomial P(x) = x^128 + x^7 + x^2 + x + 1.
 *
 *      Section 2.3 of McGrew & Viega (and Section 5.2 / Algorithm 1 of
 *      NIST SP 800-38D) defines the 128-bit bit-reduction constant:
 *          R = 11100001 || 0^120  (0xE1000000... in big-endian hex)
 *
 *      Instead of performing 8 individual 1-bit right-shifts and conditional
 *      XOR reductions with R during table generation (as described in
 *      Section 4.1), this function precomputes the net polynomial reduction
 *      for all 256 possible 8-bit (1-byte) values that fall off the low end of
 *      a 128-bit block during a full 1-byte shift.
 *
 *  Parameters:
 *      None.
 *
 *  Returns:
 *      A 256-entry array where entry [b] holds the 128-bit polynomial
 *      reduction block corresponding to shifted-out byte value 'b'.
 *
 *  Comments:
 *      None.
 */
constexpr auto MakeReductionTable()
{
    std::array<std::array<std::uint32_t, 4>, 256> R{};

    // Base reduction values for single bit positions (0x80 down to 0x01);
    // pre-calculated polynomial reductions for 8-bit shifts of single bits.
    R[128] = {0xe100'0000U, 0, 0, 0};
    R[ 64] = {0x7080'0000U, 0, 0, 0};
    R[ 32] = {0x3840'0000U, 0, 0, 0};
    R[ 16] = {0x1c20'0000U, 0, 0, 0};
    R[  8] = {0x0e10'0000U, 0, 0, 0};
    R[  4] = {0x0708'0000U, 0, 0, 0};
    R[  2] = {0x0384'0000U, 0, 0, 0};
    R[  1] = {0x01c2'0000U, 0, 0, 0};
    R[  0] = {0x0000'0000U, 0, 0, 0};

    // Populate composite byte entries using a doubling XOR loop
    for (std::size_t i = 2; i <= 128; i *= 2)
    {
        for (std::size_t j = 1; j < i; ++j)
        {
            // NOLINTBEGIN(cppcoreguidelines-pro-bounds-constant-array-index)
            R[i + j][0] = R[i][0] ^ R[j][0];
            R[i + j][1] = R[i][1] ^ R[j][1];
            R[i + j][2] = R[i][2] ^ R[j][2];
            R[i + j][3] = R[i][3] ^ R[j][3];
            // NOLINTEND(cppcoreguidelines-pro-bounds-constant-array-index)
        }
    }

    return R;
}

constexpr std::array<std::array<std::uint32_t, 4>, 256> Reduction_Table =
    MakeReductionTable();

/*
 *  MultiplyByX8()
 *
 *  Description:
 *      Multiplies a GF(2^128) field element by x^8 (performs a full-octet
 *      right-shift with 8-bit precomputed polynomial reduction).
 *
 *      In GCM's Galois field GF(2^128), shifting an element right by 8 bits
 *      (one octet) is equivalent to multiplying the polynomial by x^8.
 *      The 8 bits that fall off the low end (the lowest byte of V[3])
 *      determine the polynomial reduction required modulo
 *      P(x) = x^128 + x^7 + x^2 + x + 1.
 *
 *      Instead of performing 8 individual bitwise shifts and conditional
 *      reductions, this function shifts the entire 128-bit vector by 1 octet
 *      and applies the net reduction via a precomputed table lookup
 *      (Reduction_Table), per Section 4.1 of the GCM specification.
 *
 *  Parameters:
 *      V [in]
 *          The 128-bit block to shift and reduce in-place.
 *
 *  Returns:
 *      Nothing, though the output will be stored in V.
 *
 *  Comments:
 *      None.
 */
constexpr void MultiplyByX8(std::span<std::uint32_t, 4> V)
{
    const std::uint8_t dropped = static_cast<std::uint8_t>(V[3] & 0xFFU);

    // Shift the vector to the right by one octet
    VectorRightShiftOctet(V);

    // Apply precomputed polynomial reduction
    const auto &R = std::span(Reduction_Table)[dropped];
    V[0] ^= R[0];
    V[1] ^= R[1];
    V[2] ^= R[2];
    V[3] ^= R[3];
}

/*
 *  MultiplyByX()
 *
 *  Description:
 *      Multiplies a GF(2^128) field element by 'x' (performs a 1-bit shift
 *      with polynomial reduction).
 *
 *      In GCM's Galois field GF(2^128), multiplying an element V by 'x'
 *      corresponds to shifting the 128-bit vector right by 1 bit. If the
 *      dropped 127th bit (LSB of V[3]) is 1, the result exceeds the field
 *      degree and must be reduced modulo P(x) = x^128 + x^7 + x^2 + x + 1.
 *
 *      Reduction is performed by XORing the high word V[0] with the constant
 *      R = 0xE1000000 (representing R = 11100001 || 0^120, per NIST SP 800-38D
 *      Section 5.2 / Algorithm 1).
 *
 *  Parameters:
 *      V [in]
 *          The 128-bit block to multiply in-place.
 *
 *  Returns:
 *      Nothing, but output is placed in V.
 *
 *  Comments:
 *      None.
 */
constexpr void MultiplyByX(std::span<std::uint32_t, 4> V)
{
    constexpr std::uint32_t Divisor_R32 = 0xe100'0000;

    // Bit 127 determines a shift or both shift and perform modulo division
    const bool reduce = (V[3] & 1U) != 0;

    VectorRightShift(V);

    // Perform modulo division?
    if (reduce) V[0] ^= Divisor_R32;
}

/*
 *  BuildTableM0()
 *
 *  Description:
 *      This function will build table M0 per Algorithm 3 described in
 *      section 4.1 of gcm-revised-spec.pdf dated May 31, 2005.
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
void BuildTableM0(
    std::span<const std::uint32_t, 4> H,
    SecUtil::SecureArray<SecUtil::SecureArray<std::uint32_t, 4>, 256> &M)
{
    // M[128] <- H
    std::ranges::copy(H, M[128].begin());

    // i <- 64; while i > 0 do M[i] <- M[2i] * x; i <- i / 2
    for (std::size_t i = 64; i > 0; i /= 2)
    {
        // NOLINTBEGIN(cppcoreguidelines-pro-bounds-constant-array-index)
        M[i] = M[2 * i];
        MultiplyByX(M[i]); // Multiply by x in GF(2^128)
        // NOLINTEND(cppcoreguidelines-pro-bounds-constant-array-index)
    }

    // i <- 2; while i <= 128 ...
    for (std::size_t i = 2; i <= 128; i *= 2)
    {
        for (std::size_t j = 1; j < i; j++)
        {
            // NOLINTBEGIN(cppcoreguidelines-pro-bounds-constant-array-index)
            // M[i + j] = M[i] ^ M[j]
            M[i + j][0] = M[i][0] ^ M[j][0];
            M[i + j][1] = M[i][1] ^ M[j][1];
            M[i + j][2] = M[i][2] ^ M[j][2];
            M[i + j][3] = M[i][3] ^ M[j][3];
            // NOLINTEND(cppcoreguidelines-pro-bounds-constant-array-index)
        }
    }

    // M[0] <- 0^128
    M[0] = {0, 0, 0, 0};
}

/*
 *  BuildAllTables()
 *
 *  Description:
 *      This function will build tables M0 to M15 per Algorithm 3 described in
 *      section 4.1 of gcm-revised-spec.pdf dated May 31, 2005.
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
void BuildAllTables(
    std::span<const std::uint32_t, 4> H,
    SecUtil::SecureArray<
        SecUtil::SecureArray<SecUtil::SecureArray<std::uint32_t, 4>, 256>,
        16> &M)
{
    // Build M[0] using the algorithm from Section 4.2 (gcm_revised)
    BuildTableM0(H, M[0]);

    // Derive M[1] to M[15] with 1-byte GF shifts
    for (std::size_t table = 1; table < 16; table++)
    {
        for (std::size_t i = 0; i < 256; i++)
        {
            // NOLINTBEGIN(cppcoreguidelines-pro-bounds-constant-array-index)
            SecUtil::SecureArray<std::uint32_t, 4> v = M[table - 1][i];

            MultiplyByX8(v);

            M[table][i] = v;
            // NOLINTEND(cppcoreguidelines-pro-bounds-constant-array-index)
        }
    }
}

#endif // TERRA_DISABLE_GHASH_TABLES

} // namespace

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
 *      use_tables [in]
 *          Indicate whether tables should be computed and used.  Use of
 *          tables will improve performance when data to be encrypted
 *          increases in size.  To determine that crossover point, it's best
 *          to perform tests with and without tables, but the crossover
 *          point is generally just a couple of hundred octets.  Messages
 *          larger than that will generally benefit from using tables, thus
 *          the default for this parameter is set to true.  If your use of
 *          GHASH is for small messages, you may prefer to set this to false.
 *
 *  Returns:
 *      Nothing.
 *
 *  Comments:
 *      None.
 */
GHASH::GHASH(std::span<const std::uint8_t, 16> H, bool use_tables) :
    use_tables{use_tables},
    aad_complete{false},
    finalized{false},
    aad_length{0},
    text_length{0},
    T{},
    H{},
    Yi{}
#ifndef TERRA_DISABLE_GHASH_TABLES
    ,
    M{}
#endif // TERRA_DISABLE_GHASH_TABLES
{
    remaining_input.reserve(16);
    GetWordArray(H, this->H);
#ifndef TERRA_DISABLE_GHASH_TABLES
    if (use_tables) BuildAllTables(this->H, M);
#else
    if (use_tables) this->use_tables = false;
#endif // TERRA_DISABLE_GHASH_TABLES
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
 *      use_tables [in]
 *          Indicate whether tables should be computed and used.  Use of
 *          tables will improve performance when data to be encrypted
 *          increases in size.  To determine that crossover point, it's best
 *          to perform tests with and without tables, but the crossover
 *          point is generally just a couple of hundred octets.  Messages
 *          larger than that will generally benefit from using tables, thus
 *          the default for this parameter is set to true.  If your use of
 *          GHASH is for small messages, you may prefer to set this to false.
 *
 *  Returns:
 *      Nothing.
 *
 *  Comments:
 *      None.
 */
GHASH::GHASH(std::span<const std::uint8_t, 16> H,
             std::span<const std::uint8_t> aad,
             std::span<const std::uint8_t> text,
             bool use_tables) :
    GHASH(H, use_tables)
{
    remaining_input.reserve(16);
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
void GHASH::InputAAD(std::span<const std::uint8_t> aad)
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
void GHASH::InputText(std::span<const std::uint8_t> text)
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
    aad_length <<= 3U;
    text_length <<= 3U;

    // Re-use remaining_input as a temporary buffer
    remaining_input.resize(16);

    // Place the AAD length into the buffer
    remaining_input[ 0] = static_cast<std::uint8_t>(aad_length >> 56U);
    remaining_input[ 1] = static_cast<std::uint8_t>(aad_length >> 48U);
    remaining_input[ 2] = static_cast<std::uint8_t>(aad_length >> 40U);
    remaining_input[ 3] = static_cast<std::uint8_t>(aad_length >> 32U);
    remaining_input[ 4] = static_cast<std::uint8_t>(aad_length >> 24U);
    remaining_input[ 5] = static_cast<std::uint8_t>(aad_length >> 16U);
    remaining_input[ 6] = static_cast<std::uint8_t>(aad_length >>  8U);
    remaining_input[ 7] = static_cast<std::uint8_t>(aad_length       );

    remaining_input[ 8] = static_cast<std::uint8_t>(text_length >> 56U);
    remaining_input[ 9] = static_cast<std::uint8_t>(text_length >> 48U);
    remaining_input[10] = static_cast<std::uint8_t>(text_length >> 40U);
    remaining_input[11] = static_cast<std::uint8_t>(text_length >> 32U);
    remaining_input[12] = static_cast<std::uint8_t>(text_length >> 24U);
    remaining_input[13] = static_cast<std::uint8_t>(text_length >> 16U);
    remaining_input[14] = static_cast<std::uint8_t>(text_length >>  8U);
    remaining_input[15] = static_cast<std::uint8_t>(text_length       );

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
    PutWordArray(Yi, result);
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
    std::ranges::copy(result, Yi.begin());
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
 *      text [in]
 *          Input to be consumed by the hashing function.
 *
 *  Returns:
 *      Nothing.
 *
 *  Comments:
 *      None.
 */
void GHASH::ConsumeInput(std::span<const std::uint8_t> text)
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
                               text.first(consumed).begin(),
                               text.first(consumed).end());

        // If there is only a partial block, just return
        if (remaining_input.size() < 16) return;

        // Place the octets into the array
        GetWordArray(std::span<const std::uint8_t, 16>(remaining_input.data(),
                                                       remaining_input.size()),
                     T);

        // Determine the number of octets remaining as input
        remaining -= consumed;

        // Yi XOR A_i (or C_i)
        VectorXOR(Yi, T);

        // Multiply Yi x H
#ifndef TERRA_DISABLE_GHASH_TABLES
        if (use_tables)
        {
            MultiplyGFUsingTables(Yi);
        }
        else
        {
            MultiplyGF(Yi);
        }
#else
        MultiplyGF(Yi);
#endif // TERRA_DISABLE_GHASH_TABLES

        // Clear the remaining input buffer
        remaining_input.clear();
    }

    // Iterate over the text in complete blocks
    while (remaining >= 16)
    {
        // Place the octets into the word array
        GetWordArray(text.subspan(consumed, 16).first<16>(), T);

        // Yi+1 = Yi XOR A_i (or C_i)
        VectorXOR(Yi, T);

        // Adjust the count of remaining and consumed octets
        remaining -= 16;
        consumed += 16;

        // Multiply Yi+1 = Yi x H
#ifndef TERRA_DISABLE_GHASH_TABLES
        if (use_tables)
        {
            MultiplyGFUsingTables(Yi);
        }
        else
        {
            MultiplyGF(Yi);
        }
#else
        MultiplyGF(Yi);
#endif // TERRA_DISABLE_GHASH_TABLES
    }

    // If there are any residual octets, just store them
    if (remaining > 0)
    {
        remaining_input.insert(remaining_input.end(),
                               text.subspan(consumed, remaining).begin(),
                               text.subspan(consumed, remaining).end());
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
        GetWordArray(std::span(remaining_input).first<16>(), T);

        // Yi+1 = Yi XOR A_i (or C_i)
        VectorXOR(Yi, T);

        // Multiply Yi+1 = Yi x H
#ifndef TERRA_DISABLE_GHASH_TABLES
        if (use_tables)
        {
            MultiplyGFUsingTables(Yi);
        }
        else
        {
            MultiplyGF(Yi);
        }
#else
        MultiplyGF(Yi);
#endif // TERRA_DISABLE_GHASH_TABLES

        // Clear the remaining_input
        remaining_input.clear();
    }
}

/*
 *  GHASH::MultiplyGF()
 *
 *  Description:
 *      Perform a multiplication operation per the GCM specification in
 *      Galois Field GF(2^128).  That is, implements X = X * H.
 *
 *  Parameters:
 *      X [in/out]
 *          Input value used in a multiplication operation.
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
void GHASH::MultiplyGF(std::span<std::uint32_t, 4> X)
{
    // Copy the value of X into T
    std::ranges::copy(X, T.begin());

    // Zero X
    std::ranges::fill(X, static_cast<std::uint32_t>(0));

    // Operator over each term
    MultiplySingleTerm(0, 0x8000'0000, T, X, H);
    MultiplySingleTerm(0, 0x4000'0000, T, X, H);
    MultiplySingleTerm(0, 0x2000'0000, T, X, H);
    MultiplySingleTerm(0, 0x1000'0000, T, X, H);
    MultiplySingleTerm(0, 0x0800'0000, T, X, H);
    MultiplySingleTerm(0, 0x0400'0000, T, X, H);
    MultiplySingleTerm(0, 0x0200'0000, T, X, H);
    MultiplySingleTerm(0, 0x0100'0000, T, X, H);
    MultiplySingleTerm(0, 0x0080'0000, T, X, H);
    MultiplySingleTerm(0, 0x0040'0000, T, X, H);
    MultiplySingleTerm(0, 0x0020'0000, T, X, H);
    MultiplySingleTerm(0, 0x0010'0000, T, X, H);
    MultiplySingleTerm(0, 0x0008'0000, T, X, H);
    MultiplySingleTerm(0, 0x0004'0000, T, X, H);
    MultiplySingleTerm(0, 0x0002'0000, T, X, H);
    MultiplySingleTerm(0, 0x0001'0000, T, X, H);
    MultiplySingleTerm(0, 0x0000'8000, T, X, H);
    MultiplySingleTerm(0, 0x0000'4000, T, X, H);
    MultiplySingleTerm(0, 0x0000'2000, T, X, H);
    MultiplySingleTerm(0, 0x0000'1000, T, X, H);
    MultiplySingleTerm(0, 0x0000'0800, T, X, H);
    MultiplySingleTerm(0, 0x0000'0400, T, X, H);
    MultiplySingleTerm(0, 0x0000'0200, T, X, H);
    MultiplySingleTerm(0, 0x0000'0100, T, X, H);
    MultiplySingleTerm(0, 0x0000'0080, T, X, H);
    MultiplySingleTerm(0, 0x0000'0040, T, X, H);
    MultiplySingleTerm(0, 0x0000'0020, T, X, H);
    MultiplySingleTerm(0, 0x0000'0010, T, X, H);
    MultiplySingleTerm(0, 0x0000'0008, T, X, H);
    MultiplySingleTerm(0, 0x0000'0004, T, X, H);
    MultiplySingleTerm(0, 0x0000'0002, T, X, H);
    MultiplySingleTerm(0, 0x0000'0001, T, X, H);

    MultiplySingleTerm(1, 0x8000'0000, T, X, H);
    MultiplySingleTerm(1, 0x4000'0000, T, X, H);
    MultiplySingleTerm(1, 0x2000'0000, T, X, H);
    MultiplySingleTerm(1, 0x1000'0000, T, X, H);
    MultiplySingleTerm(1, 0x0800'0000, T, X, H);
    MultiplySingleTerm(1, 0x0400'0000, T, X, H);
    MultiplySingleTerm(1, 0x0200'0000, T, X, H);
    MultiplySingleTerm(1, 0x0100'0000, T, X, H);
    MultiplySingleTerm(1, 0x0080'0000, T, X, H);
    MultiplySingleTerm(1, 0x0040'0000, T, X, H);
    MultiplySingleTerm(1, 0x0020'0000, T, X, H);
    MultiplySingleTerm(1, 0x0010'0000, T, X, H);
    MultiplySingleTerm(1, 0x0008'0000, T, X, H);
    MultiplySingleTerm(1, 0x0004'0000, T, X, H);
    MultiplySingleTerm(1, 0x0002'0000, T, X, H);
    MultiplySingleTerm(1, 0x0001'0000, T, X, H);
    MultiplySingleTerm(1, 0x0000'8000, T, X, H);
    MultiplySingleTerm(1, 0x0000'4000, T, X, H);
    MultiplySingleTerm(1, 0x0000'2000, T, X, H);
    MultiplySingleTerm(1, 0x0000'1000, T, X, H);
    MultiplySingleTerm(1, 0x0000'0800, T, X, H);
    MultiplySingleTerm(1, 0x0000'0400, T, X, H);
    MultiplySingleTerm(1, 0x0000'0200, T, X, H);
    MultiplySingleTerm(1, 0x0000'0100, T, X, H);
    MultiplySingleTerm(1, 0x0000'0080, T, X, H);
    MultiplySingleTerm(1, 0x0000'0040, T, X, H);
    MultiplySingleTerm(1, 0x0000'0020, T, X, H);
    MultiplySingleTerm(1, 0x0000'0010, T, X, H);
    MultiplySingleTerm(1, 0x0000'0008, T, X, H);
    MultiplySingleTerm(1, 0x0000'0004, T, X, H);
    MultiplySingleTerm(1, 0x0000'0002, T, X, H);
    MultiplySingleTerm(1, 0x0000'0001, T, X, H);

    MultiplySingleTerm(2, 0x8000'0000, T, X, H);
    MultiplySingleTerm(2, 0x4000'0000, T, X, H);
    MultiplySingleTerm(2, 0x2000'0000, T, X, H);
    MultiplySingleTerm(2, 0x1000'0000, T, X, H);
    MultiplySingleTerm(2, 0x0800'0000, T, X, H);
    MultiplySingleTerm(2, 0x0400'0000, T, X, H);
    MultiplySingleTerm(2, 0x0200'0000, T, X, H);
    MultiplySingleTerm(2, 0x0100'0000, T, X, H);
    MultiplySingleTerm(2, 0x0080'0000, T, X, H);
    MultiplySingleTerm(2, 0x0040'0000, T, X, H);
    MultiplySingleTerm(2, 0x0020'0000, T, X, H);
    MultiplySingleTerm(2, 0x0010'0000, T, X, H);
    MultiplySingleTerm(2, 0x0008'0000, T, X, H);
    MultiplySingleTerm(2, 0x0004'0000, T, X, H);
    MultiplySingleTerm(2, 0x0002'0000, T, X, H);
    MultiplySingleTerm(2, 0x0001'0000, T, X, H);
    MultiplySingleTerm(2, 0x0000'8000, T, X, H);
    MultiplySingleTerm(2, 0x0000'4000, T, X, H);
    MultiplySingleTerm(2, 0x0000'2000, T, X, H);
    MultiplySingleTerm(2, 0x0000'1000, T, X, H);
    MultiplySingleTerm(2, 0x0000'0800, T, X, H);
    MultiplySingleTerm(2, 0x0000'0400, T, X, H);
    MultiplySingleTerm(2, 0x0000'0200, T, X, H);
    MultiplySingleTerm(2, 0x0000'0100, T, X, H);
    MultiplySingleTerm(2, 0x0000'0080, T, X, H);
    MultiplySingleTerm(2, 0x0000'0040, T, X, H);
    MultiplySingleTerm(2, 0x0000'0020, T, X, H);
    MultiplySingleTerm(2, 0x0000'0010, T, X, H);
    MultiplySingleTerm(2, 0x0000'0008, T, X, H);
    MultiplySingleTerm(2, 0x0000'0004, T, X, H);
    MultiplySingleTerm(2, 0x0000'0002, T, X, H);
    MultiplySingleTerm(2, 0x0000'0001, T, X, H);

    MultiplySingleTerm(3, 0x8000'0000, T, X, H);
    MultiplySingleTerm(3, 0x4000'0000, T, X, H);
    MultiplySingleTerm(3, 0x2000'0000, T, X, H);
    MultiplySingleTerm(3, 0x1000'0000, T, X, H);
    MultiplySingleTerm(3, 0x0800'0000, T, X, H);
    MultiplySingleTerm(3, 0x0400'0000, T, X, H);
    MultiplySingleTerm(3, 0x0200'0000, T, X, H);
    MultiplySingleTerm(3, 0x0100'0000, T, X, H);
    MultiplySingleTerm(3, 0x0080'0000, T, X, H);
    MultiplySingleTerm(3, 0x0040'0000, T, X, H);
    MultiplySingleTerm(3, 0x0020'0000, T, X, H);
    MultiplySingleTerm(3, 0x0010'0000, T, X, H);
    MultiplySingleTerm(3, 0x0008'0000, T, X, H);
    MultiplySingleTerm(3, 0x0004'0000, T, X, H);
    MultiplySingleTerm(3, 0x0002'0000, T, X, H);
    MultiplySingleTerm(3, 0x0001'0000, T, X, H);
    MultiplySingleTerm(3, 0x0000'8000, T, X, H);
    MultiplySingleTerm(3, 0x0000'4000, T, X, H);
    MultiplySingleTerm(3, 0x0000'2000, T, X, H);
    MultiplySingleTerm(3, 0x0000'1000, T, X, H);
    MultiplySingleTerm(3, 0x0000'0800, T, X, H);
    MultiplySingleTerm(3, 0x0000'0400, T, X, H);
    MultiplySingleTerm(3, 0x0000'0200, T, X, H);
    MultiplySingleTerm(3, 0x0000'0100, T, X, H);
    MultiplySingleTerm(3, 0x0000'0080, T, X, H);
    MultiplySingleTerm(3, 0x0000'0040, T, X, H);
    MultiplySingleTerm(3, 0x0000'0020, T, X, H);
    MultiplySingleTerm(3, 0x0000'0010, T, X, H);
    MultiplySingleTerm(3, 0x0000'0008, T, X, H);
    MultiplySingleTerm(3, 0x0000'0004, T, X, H);
    MultiplySingleTerm(3, 0x0000'0002, T, X, H);
    MultiplySingleTerm(3, 0x0000'0001, T, X, H);
}

#ifndef TERRA_DISABLE_GHASH_TABLES

/*
 *  GHASH::MultiplyGFUsingTables()
 *
 *  Description:
 *      Perform a multiplication operation per the GCM specification in
 *      Galois Field GF(2^128).  That is, implements X = X * Y.  In
 *      the specification, Y is always H and when H is expanded in table form
 *      the values to use are found in the multi-dimensional array M.
 *
 *  Parameters:
 *      X [in/out]
 *          First input value used in a multiplication operation.
 *
 *  Returns:
 *      Nothing, though the output will be stored in X.
 *
 *  Comments:
 *      This uses the table-based multiplication as defined in
 *      section 4.1 of gcm-revised-spec.pdf dated May 31, 2005.
 */
void GHASH::MultiplyGFUsingTables(std::span<std::uint32_t, 4> X)
{
    // NOLINTBEGIN(cppcoreguidelines-pro-bounds-constant-array-index)

    // Extract byte 0 (bits 31..24 of X[0]) and initialize result in Z
    const std::uint8_t b0 = static_cast<std::uint8_t>((X[0] >> 24U) & 0xFFU);
    SecUtil::SecureArray<std::uint32_t, 4> Z = M[0][b0];

    // Word 0 (Bytes 1..3)
    const std::uint8_t b1 = static_cast<std::uint8_t>((X[0] >> 16U) & 0xFFU);
    Z[0] ^= M[1][b1][0];
    Z[1] ^= M[1][b1][1];
    Z[2] ^= M[1][b1][2];
    Z[3] ^= M[1][b1][3];

    const std::uint8_t b2 = static_cast<std::uint8_t>((X[0] >> 8U) & 0xFFU);
    Z[0] ^= M[2][b2][0];
    Z[1] ^= M[2][b2][1];
    Z[2] ^= M[2][b2][2];
    Z[3] ^= M[2][b2][3];

    const std::uint8_t b3 = static_cast<std::uint8_t>(X[0] & 0xFFU);
    Z[0] ^= M[3][b3][0];
    Z[1] ^= M[3][b3][1];
    Z[2] ^= M[3][b3][2];
    Z[3] ^= M[3][b3][3];

    // Word 1 (Bytes 4..7)
    const std::uint8_t b4 = static_cast<std::uint8_t>((X[1] >> 24U) & 0xFFU);
    Z[0] ^= M[4][b4][0];
    Z[1] ^= M[4][b4][1];
    Z[2] ^= M[4][b4][2];
    Z[3] ^= M[4][b4][3];

    const std::uint8_t b5 = static_cast<std::uint8_t>((X[1] >> 16U) & 0xFFU);
    Z[0] ^= M[5][b5][0];
    Z[1] ^= M[5][b5][1];
    Z[2] ^= M[5][b5][2];
    Z[3] ^= M[5][b5][3];

    const std::uint8_t b6 = static_cast<std::uint8_t>((X[1] >> 8U) & 0xFFU);
    Z[0] ^= M[6][b6][0];
    Z[1] ^= M[6][b6][1];
    Z[2] ^= M[6][b6][2];
    Z[3] ^= M[6][b6][3];

    const std::uint8_t b7 = static_cast<std::uint8_t>(X[1] & 0xFFU);
    Z[0] ^= M[7][b7][0];
    Z[1] ^= M[7][b7][1];
    Z[2] ^= M[7][b7][2];
    Z[3] ^= M[7][b7][3];

    // Word 2 (Bytes 8..11)
    const std::uint8_t b8 = static_cast<std::uint8_t>((X[2] >> 24U) & 0xFFU);
    Z[0] ^= M[8][b8][0];
    Z[1] ^= M[8][b8][1];
    Z[2] ^= M[8][b8][2];
    Z[3] ^= M[8][b8][3];

    const std::uint8_t b9 = static_cast<std::uint8_t>((X[2] >> 16U) & 0xFFU);
    Z[0] ^= M[9][b9][0];
    Z[1] ^= M[9][b9][1];
    Z[2] ^= M[9][b9][2];
    Z[3] ^= M[9][b9][3];

    const std::uint8_t b10 = static_cast<std::uint8_t>((X[2] >> 8U) & 0xFFU);
    Z[0] ^= M[10][b10][0];
    Z[1] ^= M[10][b10][1];
    Z[2] ^= M[10][b10][2];
    Z[3] ^= M[10][b10][3];

    const std::uint8_t b11 = static_cast<std::uint8_t>(X[2] & 0xFFU);
    Z[0] ^= M[11][b11][0];
    Z[1] ^= M[11][b11][1];
    Z[2] ^= M[11][b11][2];
    Z[3] ^= M[11][b11][3];

    // Word 3 (Bytes 12..15)
    const std::uint8_t b12 = static_cast<std::uint8_t>((X[3] >> 24U) & 0xFFU);
    Z[0] ^= M[12][b12][0];
    Z[1] ^= M[12][b12][1];
    Z[2] ^= M[12][b12][2];
    Z[3] ^= M[12][b12][3];

    const std::uint8_t b13 = static_cast<std::uint8_t>((X[3] >> 16U) & 0xFFU);
    Z[0] ^= M[13][b13][0];
    Z[1] ^= M[13][b13][1];
    Z[2] ^= M[13][b13][2];
    Z[3] ^= M[13][b13][3];

    const std::uint8_t b14 = static_cast<std::uint8_t>((X[3] >> 8U) & 0xFFU);
    Z[0] ^= M[14][b14][0];
    Z[1] ^= M[14][b14][1];
    Z[2] ^= M[14][b14][2];
    Z[3] ^= M[14][b14][3];

    const std::uint8_t b15 = static_cast<std::uint8_t>(X[3] & 0xFFU);
    Z[0] ^= M[15][b15][0];
    Z[1] ^= M[15][b15][1];
    Z[2] ^= M[15][b15][2];
    Z[3] ^= M[15][b15][3];

    // NOLINTEND(cppcoreguidelines-pro-bounds-constant-array-index)

    // Copy result back into X
    std::ranges::copy(Z, X.begin());
}
#endif // TERRA_DISABLE_GHASH_TABLES

} // namespace Terra::Crypto::Cipher::GCM
