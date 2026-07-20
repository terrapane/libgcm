/*
 *  gcm_utilities.h
 *
 *  Copyright (C) 2024, 2026
 *  Terrapane Corporation
 *  All Rights Reserved
 *
 *  Author:
 *      Paul E. Jones <paulej@packetizer.com>
 *
 *  Description:
 *      This file defines utility functions utilized by the Galois Counter Mode
 *      (GCM) and GCM Hash (GHASH) functions.
 *
 *  Portability Issues:
 *      None.
 */

#include <span>
#include <cstdint>

namespace Terra::Crypto::Cipher::GCM
{

/*
 *  VectorXOR()
 *
 *  Description:
 *      Perform an XOR operation over the vectors X and Y with the result
 *      stored in X.
 *
 *  Parameters:
 *      X [in/out]
 *          First vector to use in XOR operation.
 *
 *      Y [in]
 *          First vector to use in XOR operation.
 *
 *  Returns:
 *      Nothing, though the output will be placed in X.
 *
 *  Comments:
 *      None.
 */
constexpr void VectorXOR(std::span<std::uint32_t, 4> X,
                         std::span<const std::uint32_t, 4> Y)
{
    X[0] ^= Y[0];
    X[1] ^= Y[1];
    X[2] ^= Y[2];
    X[3] ^= Y[3];
}

/*
 *  VectorRightShift()
 *
 *  Description:
 *      Shift the given vector one bit to the right.
 *
 *  Parameters:
 *      X [in/out]
 *          Vector that should be shifted to the right by one bit.
 *
 *  Returns:
 *      Nothing, though the parameter X will updated.
 *
 *  Comments:
 *      None.
 */
constexpr void VectorRightShift(std::span<std::uint32_t, 4> X)
{
    X[3] = (X[3] >> 1U) | (X[2] << 31U);
    X[2] = (X[2] >> 1U) | (X[1] << 31U);
    X[1] = (X[1] >> 1U) | (X[0] << 31U);
    X[0] = (X[0] >> 1U);
}

/*
 *  GetWordArray()
 *
 *  Description:
 *      This function will convert a 16-octet vector into an array of four
 *      32-bit words.
 *
 *  Parameters:
 *      octets [in]
 *          Octet array from which to read values to be placed into the word
 *          array.
 *
 *       words [out]
 *          The word array into which the octets are placed.
 *
 *  Returns:
 *      Nothing.
 *
 *  Comments:
 *      None.
 */
constexpr void GetWordArray(std::span<const std::uint8_t, 16> octets,
                            std::span<std::uint32_t, 4> words)
{
    words[0] = (static_cast<std::uint32_t>(octets[ 0]) << 24U) |
               (static_cast<std::uint32_t>(octets[ 1]) << 16U) |
               (static_cast<std::uint32_t>(octets[ 2]) <<  8U) |
               (static_cast<std::uint32_t>(octets[ 3])       );
    words[1] = (static_cast<std::uint32_t>(octets[ 4]) << 24U) |
               (static_cast<std::uint32_t>(octets[ 5]) << 16U) |
               (static_cast<std::uint32_t>(octets[ 6]) <<  8U) |
               (static_cast<std::uint32_t>(octets[ 7])       );
    words[2] = (static_cast<std::uint32_t>(octets[ 8]) << 24U) |
               (static_cast<std::uint32_t>(octets[ 9]) << 16U) |
               (static_cast<std::uint32_t>(octets[10]) <<  8U) |
               (static_cast<std::uint32_t>(octets[11])       );
    words[3] = (static_cast<std::uint32_t>(octets[12]) << 24U) |
               (static_cast<std::uint32_t>(octets[13]) << 16U) |
               (static_cast<std::uint32_t>(octets[14]) <<  8U) |
               (static_cast<std::uint32_t>(octets[15])       );
}

/*
 *  GetWordArray()
 *
 *  Description:
 *      This function will convert a 4-octet vector into a single 32-bit word.
 *
 *  Parameters:
 *      octets [in]
 *          Octet array from which to read values to be placed into the word
 *          array.
 *
 *       word [out]
 *          The 32-bit word into which the octets are placed.
 *
 *  Returns:
 *      Nothing.
 *
 *  Comments:
 *      None.
 */
constexpr void GetWord(std::span<const std::uint8_t, 4> octets,
                       std::uint32_t &word)
{
    word = (static_cast<std::uint32_t>(octets[ 0]) << 24U) |
           (static_cast<std::uint32_t>(octets[ 1]) << 16U) |
           (static_cast<std::uint32_t>(octets[ 2]) <<  8U) |
           (static_cast<std::uint32_t>(octets[ 3])       );
}

/*
 *  PutWordArray()
 *
 *  Description:
 *      This function will convert a 32-bit word array holding four words
 *      into an octet vector.
 *
 *  Parameters:
 *      words [in]
 *          The word array from which to read values.
 *
 *      octets [out]
 *          Octet array into which values from the word array are written.
 *
 *  Returns:
 *      Nothing.
 *
 *  Comments:
 *      None.
 */
constexpr void PutWordArray(std::span<const std::uint32_t, 4> words,
                            std::span<std::uint8_t, 16> octets)
{
    octets[ 0] = static_cast<std::uint8_t>(words[0] >> 24U);
    octets[ 1] = static_cast<std::uint8_t>(words[0] >> 16U);
    octets[ 2] = static_cast<std::uint8_t>(words[0] >>  8U);
    octets[ 3] = static_cast<std::uint8_t>(words[0]       );
    octets[ 4] = static_cast<std::uint8_t>(words[1] >> 24U);
    octets[ 5] = static_cast<std::uint8_t>(words[1] >> 16U);
    octets[ 6] = static_cast<std::uint8_t>(words[1] >>  8U);
    octets[ 7] = static_cast<std::uint8_t>(words[1]       );
    octets[ 8] = static_cast<std::uint8_t>(words[2] >> 24U);
    octets[ 9] = static_cast<std::uint8_t>(words[2] >> 16U);
    octets[10] = static_cast<std::uint8_t>(words[2] >>  8U);
    octets[11] = static_cast<std::uint8_t>(words[2]       );
    octets[12] = static_cast<std::uint8_t>(words[3] >> 24U);
    octets[13] = static_cast<std::uint8_t>(words[3] >> 16U);
    octets[14] = static_cast<std::uint8_t>(words[3] >>  8U);
    octets[15] = static_cast<std::uint8_t>(words[3]       );
}

/*
 *  PutWord()
 *
 *  Description:
 *      This function will convert a 32-bit word into a four-octet vector.
 *
 *  Parameters:
 *      word [in]
 *          The 32-bit word from which octets are extracted.
 *
 *      octets [out]
 *          Octet array into which values from the 32-bit word are written.
 *
 *  Returns:
 *      Nothing.
 *
 *  Comments:
 *      None.
 */
constexpr void PutWord(const std::uint32_t word,
                       std::span<std::uint8_t, 4> octets)
{
    octets[0] = static_cast<std::uint8_t>(word >> 24U);
    octets[1] = static_cast<std::uint8_t>(word >> 16U);
    octets[2] = static_cast<std::uint8_t>(word >>  8U);
    octets[3] = static_cast<std::uint8_t>(word       );
}

} // namespace Terra::Crypto::Cipher::GCM
